import Failure from "../../components/Failure";
import { Button, Card, Empty, PageHead, Spinner } from "../../components/ui";
import { api, LOG_PAGE } from "../../lib/api";
import { on } from "../../lib/format";
import type { AdminRecord } from "../../lib/types";
import { usePagedLog } from "../../lib/usePagedLog";
import { LogId } from "./logIds";

/** The administrative log, rendered — *who changed who may do what*.
 *
 * **This is 12b's deliverable, and it is deliberately the log rather than a group
 * manager.** Migration 022 built the table in step 011 and left it readable only through
 * `psql` and `--admin-log`, because a read route needed a tenant-admin role that did not
 * exist. So a customer's operations team could not answer *"who gave this person access
 * to the payroll agent, and when"* about a product their own staff used all day.
 *
 * The log is the right first screen behind the new role for three reasons that are not
 * about taste. It is **read-only**, so the first thing an administrator can do with a role
 * cannot break anything. It **proves the whole chain** — a row somebody granted, a 403
 * that becomes a 200, and a screen a non-administrator never sees. And it is **the thing
 * somebody actually asks for after an incident**, which no other administrative screen is
 * yet.
 *
 * ## Newest first, and *Show older* — 110f, plan 107 D10
 *
 * For twenty steps this was the newest two hundred rows, oldest first, with a hint that
 * older records were not shown. The row somebody came for was at the bottom, and the one
 * before the window was unreachable from a browser — which is exactly what the first
 * administrator who needed the log found. Now the newest page is on top and **Show
 * older** appends the page before it, keyed on the oldest id shown rather than on an
 * offset; `usePagedLog` argues why. The cap and its hint are gone because they no longer
 * describe anything: the page is not the window.
 *
 * ## Why there is no nav item for people who are not administrators
 *
 * `App.tsx` renders this route for anybody who types the URL, and it will answer 403 with
 * the server's own sentence. That is correct and is not the same thing as hiding it:
 * `AppShell` asks `GET /me` and only offers the link to an administrator, because a
 * control that exists and refuses the person who pressed it reads as a bug — which is
 * 10d's `your_role` lesson, one level up, and the reason `/me` exists at all.
 *
 * ## Rendering `detail` rather than parsing it
 *
 * `detail` differs per action by design: a role, a grantee, a list of field names, a
 * scope. A screen that switched on `action` to render each shape would be a second
 * vocabulary of the log's vocabulary, and it would render nothing at all for the next
 * action somebody adds. So the keys are printed, sorted, exactly as `--admin-log` prints
 * them — and the two agreeing is worth more than either being prettier.
 */
export default function AdminPage() {
  const { rows, error, loading, more, fetching, older } = usePagedLog(
    (before, limit) => api.adminAudit({ before, limit }),
    LOG_PAGE,
    [],
  );

  return (
    <>
      <PageHead
        title="Audit log"
        lede="Changes to access in this workspace: grants, shares, group membership, tool approvals and roles. Newest first."
      />

      {loading && <Spinner label="Loading…" />}
      {error && <Failure error={error} />}

      {rows && rows.length === 0 && (
        <Empty title="No changes yet">
          <p className="sentence">
            Grants, shares, group changes, tool approvals and role changes appear here.
          </p>
        </Empty>
      )}

      {rows && rows.length > 0 && (
        // The count is what is on screen, and the button beneath says whether there is
        // more — so the title no longer has to choose between "200 changes" (reads as
        // the total) and "the 200 most recent" (a window nobody could see past).
        <Card title={`${rows.length} ${rows.length === 1 ? "change" : "changes"}`}>
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Target</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((record) => (
                // Keyed by the store's own sequence number since 110f. The index was
                // right while there was no id a client could see; now that a page is
                // appended beneath the last, a positional key would re-render the
                // whole table on every *Show older*.
                <tr key={record.id}>
                  <td className="mono">{on(record.ts)}</td>
                  <td className="mono">
                    {record.actor_kind}:{record.actor_id}
                  </td>
                  <td className="mono">{record.action}</td>
                  <td className="mono">
                    {record.target_kind}:
                    <LogId kind={record.target_kind} id={record.target_id} />
                  </td>
                  <td className="row-sub">{describe(record)}</td>
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

/** `detail` as one line, sorted, with empty values dropped.
 *
 * The same projection `--admin-log` does, so the screen and the terminal say the same
 * thing about the same record. Empty values are dropped rather than rendered as `[]`,
 * because a record's `detail` carries the keys its *action* uses and a reader comparing
 * two rows should see what differs rather than what was never set.
 */
export function describe(record: AdminRecord): string {
  return Object.entries(record.detail ?? {})
    .filter(([, value]) => value !== null && value !== "" && !isEmptyCollection(value))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${render(value)}`)
    .join(", ");
}

function isEmptyCollection(value: unknown): boolean {
  if (Array.isArray(value)) return value.length === 0;
  if (value && typeof value === "object") return Object.keys(value).length === 0;
  return false;
}

function render(value: unknown): string {
  if (Array.isArray(value)) return value.join(" ");
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value);
}
