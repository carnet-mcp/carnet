import { useSearchParams } from "react-router-dom";

import Failure from "../../components/Failure";
import { Button, Card, Empty, PageHead, Spinner } from "../../components/ui";
import { api, LOG_PAGE } from "../../lib/api";
import { on } from "../../lib/format";
import { DENIAL_RESOURCE_KINDS } from "../../lib/types";
import type { DenialRecord } from "../../lib/types";
import { usePagedLog } from "../../lib/usePagedLog";
import { LogId } from "./logIds";

/** The access-denial log, rendered — *who tried, and was refused*.
 *
 * **This is 035b's deliverable, and the gap it closes is the plainest kind in plan 035.**
 * `GET /admin/denials` has been live since step 015. It is admin-gated, it carries both
 * incident filters, it has a CLI reader, it has route tests, and since migration 040 it
 * covers the MCP door's refusals too. What it never had was a browser. The log that
 * answers the question people actually ask after an incident was reachable from a shell
 * and invisible from the product, for twenty steps.
 *
 * ## What a denial row is, and why the log has to exist at all
 *
 * In this product **absence is denial, and denial looks like absence**: a person with no
 * grant on an agent gets the same 404 as somebody naming an agent that does not exist,
 * deliberately, because a 403 sweep over plausible names enumerates every agent in the
 * company. That is right at the door and it means the refusal leaves no trace in
 * anything the caller can see. This table is where it leaves one.
 *
 * ## `required` and `held` are one fact in two columns
 *
 * A `user` probing for `editor` reads completely differently from a stranger probing at
 * all, and the pair is what says which. So `held: ""` renders as the word **nothing**
 * rather than as an empty cell — for the reason `DoorTrafficPage` renders *"nobody
 * named"*: an empty value here is an answer the server gave, and blank space reads as a
 * field it failed to send.
 *
 * ## The kind is a value, never a switch
 *
 * `resource_kind` is printed the way `AdminPage` prints `target_kind` — a plain column
 * value. A kind this frontend has never heard of renders correctly on the day the server
 * starts writing it, which is what happened to `tool` and will happen again.
 *
 * The *filter* chips are the one place the vocabulary is copied, and the cost of that
 * copy is bounded on purpose: a kind missing from the list is a missing shortcut, not a
 * missing row. See `DENIAL_RESOURCE_KINDS` in `types.ts`.
 *
 * ## Filtering is the server's job
 *
 * Every filter here is a query parameter, never a `.filter()` on what arrived. The list
 * is a page of the most recent records, so a client narrowing that page would be
 * answering *"which of these came from the door"* with *"which of the last hundred"* —
 * which is the same lie as silent truncation, and the reason the route caps `limit` in
 * its signature rather than in a branch.
 *
 * The filters were React state and deliberately **not** in the URL until 110f, for one
 * concrete reason: `Failure` rendered every 422 as *"This agent's configuration is not
 * valid"*, and a filter in the URL is one keystroke from `?kind=banana`. 066 retitled
 * the 422 and put the request log's filters in its URL; plan 107 D10 brought this page
 * into line, so a filtered view is a link an administrator can send — the argument this
 * codebase makes everywhere else, and the one thing that fact had been overruling.
 * Read straight from `useSearchParams` with no local mirror, for `DoorTrafficPage`'s
 * reason: two values free to disagree, silently.
 *
 * Newest first, a page at a time, keyed on the oldest id shown — `usePagedLog`. An id
 * in a cell links to its page where one exists and narrows the log otherwise
 * (`logIds`), so this page and the request log agree about which ids go somewhere.
 *
 * No polling. The log is a record of what happened, not a thing in flight.
 */
export default function DenialsPage() {
  const [params, setParams] = useSearchParams();
  const kind = params.get("kind") ?? "";
  const principalId = params.get("principal_id") ?? "";
  const resourceId = params.get("resource_id") ?? "";

  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };
  const setKind = (value: string) => set("kind", value);
  const setPrincipalId = (value: string) => set("principal_id", value);
  const setResourceId = (value: string) => set("resource_id", value);

  const { rows: data, error, loading, more, fetching, older } = usePagedLog(
    (before, limit) =>
      api.adminDenials({
        before,
        limit,
        resourceKind: kind || undefined,
        principalId: principalId || undefined,
        resourceId: resourceId || undefined,
      }),
    LOG_PAGE,
    [params.toString()],
  );

  const filtered = Boolean(kind || principalId || resourceId);
  const clear = () => setParams(new URLSearchParams(), { replace: true });

  return (
    <>
      <PageHead
        title="Access denied"
        lede="Requests that were denied: an agent the user cannot see, an admin page they cannot open, or a tool their token is not granted. Newest first."
      />

      <div className="log-filters">
        <span className="muted">Kind:</span>
        <Button kind={kind === "" ? "primary" : "quiet"} onClick={() => setKind("")}>
          all
        </Button>
        {DENIAL_RESOURCE_KINDS.map((option) => (
          <Button
            key={option}
            kind={kind === option ? "primary" : "quiet"}
            onClick={() => setKind(option)}
          >
            {option}
          </Button>
        ))}
        {filtered && (
          <Button kind="quiet" onClick={clear}>
            Clear filters
          </Button>
        )}
      </div>

      {(principalId || resourceId) && (
        <p className="muted sentence">
          {principalId && (
            <Narrowed
              label={`Only requests by ${principalId}.`}
              clearLabel="Clear actor filter"
              onClear={() => setPrincipalId("")}
            />
          )}
          {resourceId && (
            <Narrowed
              label={`Only requests for ${resourceId}.`}
              clearLabel="Clear target filter"
              onClear={() => setResourceId("")}
            />
          )}
        </p>
      )}

      {loading && <Spinner label="Loading…" />}
      {error && <Failure error={error} />}

      {data && data.length === 0 && !filtered && (
        <Empty title="No denied requests">
          <p className="sentence">
            Denied requests appear here: an agent the user cannot see, an admin page they
            cannot open, or a tool their token is not granted.
          </p>
        </Empty>
      )}

      {data && data.length === 0 && filtered && (
        // Told apart from the empty log on purpose. "Nothing was ever refused" and "your
        // filter matched nothing" look identical and are different facts, and one of them
        // has something to do about it.
        <Empty title="No matching requests">
          <p className="sentence">Remove a filter to widen the search.</p>
          <Button kind="quiet" onClick={clear}>
            Clear filters
          </Button>
        </Empty>
      )}

      {data && data.length > 0 && (
        <Card
          title={`${data.length} denied ${data.length === 1 ? "request" : "requests"}`}
        >
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Actor</th>
                <th>Target</th>
                <th>Required</th>
                <th>Held</th>
              </tr>
            </thead>
            <tbody>
              {data.map((record) => (
                // Keyed by the store's sequence number since 110f; the index was right
                // only while a page was never appended to.
                <tr key={record.id}>
                  <td className="mono">{on(record.ts)}</td>
                  <td className="mono">
                    {record.principal_kind}:
                    <LogId
                      kind={record.principal_kind}
                      id={record.principal_id}
                      onPick={setPrincipalId}
                      title="Show only requests by this actor"
                    />
                  </td>
                  <td className="mono">
                    {record.resource_kind}
                    {record.resource_id ? (
                      <>
                        {": "}
                        <LogId
                          kind={record.resource_kind}
                          id={record.resource_id}
                          onPick={setResourceId}
                          title="Show only requests for this target"
                        />
                      </>
                    ) : null}
                  </td>
                  <td className="mono">{record.required}</td>
                  <td>
                    <Held record={record} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
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

/** One narrowing in force, and the way out of it.
 *
 *  **Each filter is dropped on its own**, which is not what this page did first. The
 *  chips could always clear the kind, so the only way to drop a principal was *Show
 *  everything* — which threw away the kind as well. Narrowing to one person and then
 *  widening the kind is the ordinary shape of an incident, and it was a dead end: the
 *  only route back went through the state you had just spent two clicks leaving. */
function Narrowed({
  label,
  clearLabel,
  onClear,
}: {
  label: string;
  clearLabel: string;
  onClear: () => void;
}) {
  return (
    <span className="narrowed">
      {label}{" "}
      <button type="button" className="filter-value" onClick={onClear}>
        {clearLabel}
      </button>
    </span>
  );
}

/** What the principal actually held, which is `""` far more often than not.
 *
 *  Rendered as a word rather than as an empty cell. `""` is the server's answer and it
 *  means *nothing at all* — the headline case, a stranger with no access whatsoever —
 *  and the difference between that and a `user` reaching for `editor` is the entire
 *  reason this column sits beside `required`. A blank cell would read as a field that
 *  failed to arrive. */
export function Held({ record }: { record: DenialRecord }) {
  if (!record.held) return <span className="muted">nothing</span>;
  return <span className="mono">{record.held}</span>;
}
