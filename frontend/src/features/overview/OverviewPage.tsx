import type { ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";

import Failure from "../../components/Failure";
import { Button, Card, Empty, PageHead, Spinner, Stats, Tabs } from "../../components/ui";
import type { Tab } from "../../components/ui";
import { BarStack, Figure, HBar, Heat, Meter, TrendLine } from "../../components/ui/charts";
import type { Series } from "../../components/ui/charts";
import { api } from "../../lib/api";
import { money, on, tokens } from "../../lib/format";
import { OVERVIEW_WINDOWS } from "../../lib/types";
import type {
  DoorDay,
  LeaderboardTail,
  Overview,
  RefusalDay,
} from "../../lib/types";
import { useResource } from "../../lib/useResource";
import { useAdmin } from "../../lib/me";

/** The overview — what came through the door, drawn for the person answerable for it.
 *
 * **Step 041b, and the page is door-first because the door is the product.** People
 * connect their own assistant to `/mcp` and every tool call goes through the broker,
 * scoped, credentialled and audited. Every series on it is read from the door's own
 * rows in `audit`. `docs/PREMISE.md` is the whole argument; this page is what it looks
 * like.
 *
 * The ordering is the argument made visible: somebody who screenshots the top third has
 * screenshotted the value proposition — volume, and the fact that every unit of it was
 * brokered, attributed and revocable.
 *
 * ## Who this is for, and the tension in that
 *
 * A manager or a compliance owner who will never read a log. They are not who the route
 * lets in: `/admin/overview` is admin-gated, because tenant-wide governance data is what
 * it is, and the only role that may read it today is platform `admin`. So the audience
 * in practice is the administrators who brief the managers, and the page is built so a
 * screenshot *is* the briefing — every figure prints its window total in text beside it,
 * and every figure's numbers are one disclosure away. A read-only `viewer` role is the
 * honest fix and is its own step.
 *
 * ## Two derivations happen here rather than on the server, and both are arithmetic
 *
 * **The door stack is made disjoint before it is drawn.** `errored` and `oversize` are
 * bands *within* `allowed` — a call that was permitted and then failed is both — so
 * stacking the four fields as they arrive would draw a column taller than the day's
 * traffic. `admitted = allowed − errored − oversize` is the segment that makes the four
 * add up. The wire keeps the overlapping shape because it is the truthful one; the chart
 * needs a partition, and turning one into the other is a subtraction, not a fact.
 *
 * **The success figures are computed from their own numerators.** The route ships no
 * ratios: a percentage sent beside the two numbers it came from is a third number that
 * can drift from them.
 *
 * ## Cost
 *
 * **A door call spends no model tokens of its own**, so volume against ceilings is most
 * of the cost question and the headroom meter is the answer. Where a brokered call does
 * reach a model (045c) the connector reports what it spent, and that is the money on
 * this page — priced against a list that names itself beside the figure, with the
 * models it could not value listed. *"A wrong number on a screen labelled cost is
 * worse than no screen"*, and an estimate that says what it was computed from is a
 * different object from one that does not.
 *
 * ## Who sees what
 *
 * `/admin/overview` is admin-gated with its own written argument; a non-administrator
 * is told so on the page rather than handed a nav item that leads to a 403.
 *
 * ## What is still deliberately not on this page
 *
 * **No alerting, no thresholds, no filters beyond the window.** This is a record. The one
 * thing on it that *is* a control lives elsewhere: the daily allowance is enforced at the
 * door, and this page only reports where today stands against it.
 */
/** The window a URL asked for, or 30. Step 066.
 *
 *  **The bound is the server's, restated here on purpose.** `GET /admin/overview` declares
 *  `days: int = Query(ge=1, le=3650)`, so a value outside that is a **422** — not a
 *  clamp — and with `days` in the URL that is one keystroke away: `?days=5000` renders a
 *  failure notice where the page should be.
 *
 *  That is exactly the rule this step wrote down for `?view=` and then had to be reminded
 *  of: *a URL somebody mistyped should show them the page, not a fault*. So anything the
 *  route would refuse is treated as an absent value.
 *
 *  What is **not** copied here is the list of offered windows. A value the route accepts
 *  but does not offer — `?days=45` — is passed through and the server clamps it to the
 *  nearest and says so in `window.clamped`, which the page then prints. Clamping here as
 *  well would silence that sentence and make the page lie about what it drew.
 *
 *  `Number` rather than `parseInt`, so `"7.5"` and `"7abc"` are rejected instead of
 *  becoming 7: both are refusals at the route (`int`), and a client that quietly rounded
 *  would draw a window nobody asked for. */
export function readWindow(asked: string | null): number {
  const value = Number(asked);
  const usable =
    asked !== null &&
    asked !== "" &&
    Number.isInteger(value) &&
    value >= 1 &&
    value <= 3650;
  return usable ? value : 30;
}

export default function OverviewPage() {
  // **The window is in the URL now, and it is one line for a reason that took a step to
  // arrive.** 048 put the *pane* in `?view=` and deliberately left `days` in `useState`:
  // *"putting it in the query string is right and is one line, but it is a change to
  // what a link means that nobody asked for, and it belongs in its own step beside the
  // same question for `/admin/door-calls`."* This is that step — the door's log grows a
  // filter bar in the same change, so the two screens start agreeing about what a shared
  // link carries rather than diverging further.
  //
  // The failure it closes is 048's own: the first person who sets this to 90 days, sends
  // the link, and is asked why the recipient is looking at a month.
  //
  // An absent or unparseable value falls back to 30 rather than erroring, on `?view=`'s
  // rule: a URL somebody mistyped should show them the page, not a fault. The server
  // clamps whatever survives that to the nearest window it offers and says so.
  const [params, setParams] = useSearchParams();
  const days = readWindow(params.get("days"));
  const setDays = (next: number) => {
    const query = new URLSearchParams(params);
    query.set("days", String(next));
    // `replace`, matching the tab strip: four clicks through the windows should not put
    // four entries in the reader's history and make Back mean "the window before last".
    setParams(query, { replace: true });
  };
  // One fetch, and it is the tenant's: `/admin/overview` is admin-gated with its own
  // written argument, and a non-administrator's guaranteed 403 is not worth a request.
  const { admin, settled } = useAdmin();
  const door = useResource(
    () => (admin ? api.overview(days) : Promise.resolve(null)),
    [admin, days],
  );

  return (
    <>
      <PageHead
        title="Overview"
        lede={
          <>
            What came through the MCP door: how much, from whom, on whose behalf, what
            it spent and what was refused. A record rather than a control: nothing on
            this page changes anything.
          </>
        }
      />

      <div className="log-filters">
        <span className="muted">Window:</span>
        {OVERVIEW_WINDOWS.map((option) => (
          <Button
            key={option}
            kind={days === option ? "primary" : "quiet"}
            onClick={() => setDays(option)}
          >
            {/* "Today", not "1 day". Step 066: the one-day window buckets by the hour and
                what a reader wants from it is *what is happening now* — a button labelled
                "1 day" describes the arithmetic, and this one describes the question. */}
            {option === 1 ? "Today" : `${option} days`}
          </Button>
        ))}
      </div>

      {/* The door half. Absent for a non-administrator rather than refused-with-an-error:
          they were never offered it, and a `Failure` where a section belongs would report
          a fault where there is only a boundary. `settled` keeps the beat of blank from
          becoming a flash of "nothing here" for an administrator whose `/me` is in
          flight — `useAdmin` documents the same rule. */}
      {settled && admin ? (
        <>
          {door.error ? <Failure error={door.error} /> : null}
          {door.loading ? <Spinner /> : null}
          {door.data ? <Body data={door.data} /> : null}
        </>
      ) : null}

      {/* **A non-administrator has nothing on this page**, and a blank page under a
          heading reads as a fault. So the boundary is stated instead. Not a `Failure` —
          nothing failed, and there is nothing here to retry. */}
      {settled && !admin ? (
        <Card>
          <Empty title="Nothing on this page is yours to read yet">
            This deployment is the MCP door: it brokers calls for assistants that connect
            to it. What came through the door — the traffic,
            what it spent, and what was refused — is tenant-wide, and reading it needs the
            administrator role. Your own credentials and what each has spent are on{" "}
            <strong>Tokens</strong>.
          </Empty>
        </Card>
      ) : null}
    </>
  );
}

// The series definitions. Colours are `var(--chart-*)` without exception — the token
// layer is where light and dark are decided, and where the palette was validated against
// these exact surfaces. A literal here would be a colour nobody checked.
// **Two segments, and the third and fourth were taken out after looking at the page.**
// The first build drew four — admitted, errored, too large, refused — and two things were
// wrong with it. The validator: `--chart-2` beside `--chart-4` is ΔE 13.7 for a reader
// with full colour vision, below the floor, so *errored* and *too large* could never sit
// next to each other however the stack was ordered. And the rendering: with refusals at
// ~11% and errors at ~4%, the upper bands were slivers that said nothing at a glance, and
// the one at the top was `--chart-3` — a green cap on a governance chart, which reads as
// *good* to anybody not consulting the legend.
//
// Two disjoint segments answer the question the figure asks — how much arrived, and how
// much of it the broker turned away. Every outcome band survives in full under *Show the
// numbers*, and the error rate is in this figure's own total.
const DOOR_SERIES: Series[] = [
  { key: "admitted", label: "Admitted", color: "var(--chart-1)" },
  { key: "denied", label: "Refused", color: "var(--chart-2)" },
];

// Ordinal, not categorical — one hue, dark to light, because verified → asserted → none
// is a trust ordering and the reader should see the order in the colour.
const IDENTITY_SERIES: Series[] = [
  { key: "verified", label: "Verified", color: "var(--chart-step-1)" },
  { key: "asserted", label: "Asserted", color: "var(--chart-step-2)" },
  { key: "none", label: "Nobody named", color: "var(--chart-step-3)" },
];

// **Four drawn bands over five facts, and the fold is the token layer's own rule rather
// than a shortcut.** 045b split the door's ceiling in two — too many *calls* and too much
// *money* — and `tokens.css` is explicit that a fifth categorical series is not a
// generated fifth hue: it is "a fold into 'other' or a second figure". A fifth colour here
// would be one nobody validated against these surfaces, on the page built to be trusted at
// a glance.
//
// So the two door ceilings stack as one segment and the numbers under *Show the numbers*
// carry them apart, and the door stack draws two of its four bands with the rest in
// the table. What is lost is telling the two ceilings apart *by eye*; what is kept
// is a stack that still sums to the day's refusals, which is the property a stacked chart
// is worthless without.
const REFUSAL_SERIES: Series[] = [
  { key: "policy", label: "Policy", color: "var(--chart-1)" },
  { key: "ceiling", label: "Door ceiling", color: "var(--chart-2)" },
  { key: "run_budget", label: "Run budget", color: "var(--chart-3)" },
  { key: "access", label: "Access", color: "var(--chart-4)" },
];

const LATENCY_SERIES: Series[] = [
  { key: "median_ms", label: "Median", color: "var(--chart-step-1)" },
  { key: "p95_ms", label: "95th percentile", color: "var(--chart-step-2)" },
];

// 066a. **One series, and it was two until the page was looked at.** A day's total bytes
// and a single response's 95th percentile are two measures of different scale — millions
// against thousands — so on one axis the percentile drew as a flat line along the floor.
// That is `charts.tsx`' opening rule ("two measures of different scale are two figures")
// broken at the callsite, and the fix is not a second figure: the daily total is the
// traffic chart times an average size, so it belongs in the table rather than in ink.
//
// One series means `Figure` draws no legend, which is right — with one colour the heading
// already says what is plotted.
const BYTES_SERIES: Series[] = [
  { key: "p95_bytes", label: "95th percentile response", color: "var(--chart-step-1)" },
];


const pct = (part: number, whole: number) =>
  whole > 0 ? `${Math.round((part / whole) * 100)}%` : "—";

// --- the road from a number to its calls. Step 066 ------------------------------------
//
// **The finding this answers, in one sentence: no bar, tile or row on this page linked
// to anything.** The aggregate and the record were two screens with no edge between
// them, so a reader who saw a spike had a number and no way down to the calls that made
// it — and `/admin/door-calls` took `limit` and nothing else, so there was no URL a bar
// could have linked to even if one had wanted to.
//
// Every link below is a query the door's log can now answer, and every one carries the
// window's own dates so a drill-down inherits what the reader was looking at rather than
// silently widening to the log's default page.

/** `/admin/door-calls` with these filters, and the window's dates unless overridden.
 *
 *  One builder rather than template strings at a dozen call sites, because the mistake it
 *  prevents is a link that quietly drops `since` and lands the reader in the whole log
 *  looking at a number that came from thirty days.
 *
 *  Blank values are omitted rather than sent — the server refuses a closed vocabulary it
 *  does not recognise, which is correct and is not what an empty string means here. */
function toDoorLog(
  window: { since: string; until: string },
  filters: Record<string, string | undefined> = {},
): string {
  const query = new URLSearchParams({ since: window.since, until: window.until });
  for (const [key, value] of Object.entries(filters)) if (value) query.set(key, value);
  return `/admin/door-calls?${query}`;
}

/** The day (or hour) a chart column covers, as the log's `since`/`until`.
 *
 *  An hour bucket is `2026-08-31T14`, and the log filters by **date** — so an hourly
 *  column links to its whole day. That is a widening and it is stated rather than hidden:
 *  narrowing to the hour would need a timestamp filter the route does not have, and a
 *  link that silently returned the day's calls while the column showed the hour's would
 *  be the worse of the two. The log's own timestamps let a reader finish the job. */
const bucketDay = (bucket: string) => bucket.split("T")[0];

/** How this window compares with the one before it, as a sentence and never a colour.
 *
 *  **Ink, not green and red**, which is the decision rather than the default: refusals
 *  falling and traffic falling are opposite news, and an arrow that decided for the
 *  reader would be wrong on half the tiles it appeared on.
 *
 *  `null` where there is nothing to compare against — a previous window of zero is not a
 *  denominator, and "up ∞%" is what dividing by it produces. The words say so instead. */
/** A **share**'s movement, in percentage points. Step 066.
 *
 *  The tile beside this reads `54%`, and putting `delta`'s output under it said
 *  `+12% on the window before` — where the 12% was the movement of the *count*. Two
 *  percentages one line apart measuring different things, and the reader has no way to
 *  see which is which: 54% is a share and +12% is a growth rate, and the natural reading
 *  of the pair is that the share moved from 42% to 54%.
 *
 *  So a share compares as a share, in points, and says "points" out loud. It is the same
 *  bug as reporting a move from 40% to 44% as "up 10%" — true of the ratio, and not what
 *  anybody reads. */
function shareDelta(
  part: number,
  whole: number,
  beforePart: number | undefined,
  beforeWhole: number | undefined,
): string | null {
  if (beforePart === undefined || !beforeWhole || !whole) return null;
  const points = Math.round((part / whole) * 100) - Math.round((beforePart / beforeWhole) * 100);
  if (points === 0) return "level on the window before";
  return `${points > 0 ? "+" : ""}${points} points on the window before`;
}

function delta(now: number, before: number | undefined): string | null {
  if (before === undefined) return null;
  if (before === 0) return now === 0 ? null : "none in the window before";
  const change = Math.round(((now - before) / before) * 100);
  if (change === 0) return "level on the window before";
  return `${change > 0 ? "+" : ""}${change}% on the window before`;
}

/** What a capped leaderboard cut, as the line drawn under it. Step 066.
 *
 *  Returns `null` when nothing was cut, so a figure that is showing everything says
 *  nothing about truncation — a permanent "and no more" is noise on every page it appears
 *  on, and this one would carry five of them. */
function tailLine(
  tail: LeaderboardTail,
  noun: string,
  href: string,
): ReactNode {
  if (!tail.n) return null;
  return (
    <>
      {/* `Link`, never `<a href>` — a full navigation drops the in-memory token and
          signs the reader out. `charts.tsx`' `Mark` carries the argument. */}
      <Link to={href}>
        {tail.n.toLocaleString()} more {tail.n === 1 ? noun : `${noun}s`}
      </Link>{" "}
      not shown, with {tail.calls.toLocaleString()}{" "}
      {tail.calls === 1 ? "call" : "calls"} between them
      {tail.denied ? ` — ${tail.denied.toLocaleString()} refused` : ""}.
    </>
  );
}

/** "top 15 of 18", or just the count when the list is complete. */
const ofTotal = (shown: number, total: number, noun: string) => {
  // `Math.max`, so a count that arrives smaller than the list it describes cannot print
  // "0 tools" over fifteen drawn bars. It should never happen — both come from one
  // statement — but every `*_count` here has a `.get(..., 0)` default on the server for
  // a store that predates the key, and a defaulted 0 under a full leaderboard is a
  // caption that contradicts the picture beside it.
  const real = Math.max(total, shown);
  return real > shown
    ? `top ${shown} of ${real.toLocaleString()} ${noun}s`
    : `${real.toLocaleString()} ${real === 1 ? noun : `${noun}s`}`;
};

/** The day's traffic, as two disjoint parts.
 *
 *  `allowed` and `denied` are the only two fields on `DoorDay` that partition it —
 *  `errored` and `oversize` are bands *within* `allowed`, so a stack of all four would
 *  draw a column taller than the traffic it describes. That trap is the reason this
 *  function exists at all rather than the rows going straight to the chart. */
function partition(rows: DoorDay[]) {
  return rows.map((row) => ({
    day: row.day,
    admitted: row.allowed,
    denied: row.denied,
  }));
}

/** The five terminal statuses folded to four bands. `cancelled` and `interrupted` are
 *  one band because they are one thing to a reader — the run stopped without answering
 *  and not because the agent failed — and a fifth colour to separate two rare statuses
 *  would cost more than it says. Both survive in full under *Show the numbers*. */
/** The day's refusals, with the door's two ceilings drawn as one.
 *
 *  `ceiling` and `door_spend` are disjoint facts about the same credential — it made too
 *  many calls, or it spent too much money — and both are the door refusing on an
 *  allowance. Summed for the stack, kept apart in the table below it. See
 *  `REFUSAL_SERIES` for why this is a fold rather than a fifth colour. */
function refusalBands(rows: RefusalDay[]) {
  return rows.map((row) => ({
    day: row.day,
    policy: row.policy,
    ceiling: row.ceiling + row.door_spend,
    run_budget: row.run_budget,
    access: row.access,
  }));
}

// The four token bands, ordinal rather than categorical: input, cache-read, cache-write
// and output are one measure at four prices, not four unrelated things. So the one-hue
// ramp (`--chart-step-*`) plus `--chart-2` for output, which is the band a reader
// actually looks for — it is the only one the model produced.
function Body({ data }: { data: Overview }) {
  const { totals, window: win, headroom } = data;
  // **A previous window with no traffic at all is no comparison, not a set of zeroes.**
  // Found by looking at the rendered page: on a deployment younger than its own window
  // every tile read "none in the window before", six times in a row — which is true of
  // each one and, said six times, is one fact about the deployment dressed as six facts
  // about the figures.
  //
  // So the comparison is dropped whole when the window before this one had no door
  // traffic. `door_calls` is the test rather than each tile's own number, because the
  // question is whether there *was* a previous window worth comparing against, and door
  // traffic is what this page counts.
  const before = data.previous?.door_calls ? data.previous : undefined;
  const doorRows = partition(data.door_calls);

  const traffic = totals.door_calls;
  const errored = data.door_calls.reduce((sum, row) => sum + row.errored, 0);
  // Administrative change is one row per (day, family) rather than a dense series — a
  // dense version would be every family on every day, almost all zeros. Folded to
  // per-family window totals, which is the shape a reader asks for anyway: *what kind
  // of change happened this month*, not *which Tuesday*.
  const families = new Map<string, number>();
  for (const row of data.admin_actions) {
    families.set(row.family, (families.get(row.family) ?? 0) + row.count);
  }
  const changes = [...families.entries()]
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value || a.name.localeCompare(b.name));

  // Step 048. Which pane is showing lives in `?view=`, never in component state: this
  // repo has said twice that *"a tab index is not a URL"* — once for `/admin/*`'s
  // sections and once for this page's own route, *"because this is what gets sent to a
  // manager."* A link to the cost tab has to open on the cost tab.
  const [params, setParams] = useSearchParams();
  const select = (id: string) => {
    const next = new URLSearchParams(params);
    next.set("view", id);
    // `replace`, so six clicks through the strip do not put six entries in the reader's
    // history and make Back mean "the tab before last".
    setParams(next, { replace: true });
  };

  // Step 048. The panes: each one is the figures that answer a single question a reader
  // arrives with. No figure is reworded, merged or dropped on the way in — a tab decides
  // what is *drawn*, never what is asked for, so switching panes costs nothing, cannot
  // fail, and cannot show two figures that straddled a write and disagree.
  //
  // The `section-head` headings this page used to carry — "The door", "Refusals" —
  // are gone: the tab strip is that heading now, and printing both would name every
  // pane twice.
  const trafficPane = (
    <>
      <Figure
        title="Calls per day"
        lede={
          <>
            Everything that arrived, and how much of it the broker turned away. What
            happened to an admitted call afterwards — the vendor failing, or a response
            past the size cap — is counted in the error rate beside this and broken out
            in full under <em>Show the numbers</em>.
          </>
        }
        total={`${traffic.toLocaleString()} calls · ${pct(errored, traffic)} errored`}
        series={DOOR_SERIES}
        table={
          <DayTable
            rows={data.door_calls}
            // All six bands since 066a. `ok` and `unknown` were on the wire's CHECK
            // since the table existed and on no screen — and the four outcome columns do
            // not sum to `allowed`, because an admitted call the server recorded no
            // outcome for is in none of them.
            columns={[
              "allowed", "denied", "ok", "errored", "oversize", "unknown",
            ]}
          />
        }
      >
        <BarStack
          rows={doorRows}
          series={DOOR_SERIES}
          label="Door calls per day"
          // Step 066. A column opens that day's calls; its *Refused* band opens that
          // day's refusals, which is a different question and so a different query.
          href={(row, s) =>
            toDoorLog(
              { since: bucketDay(row.day), until: bucketDay(row.day) },
              { decision: s.key === "denied" ? "deny" : undefined },
            )
          }
        />
      </Figure>

      <Figure
        title="How long a call took"
        lede={
          <>
            Admitted calls only — a refusal has no duration to report, and a day with
            none is a gap here rather than a zero. Which <em>tool</em> is slow is under{" "}
            <strong>Callers &amp; tools</strong>; this is the door as a whole.
          </>
        }
        series={LATENCY_SERIES}
        table={<DayTable rows={data.door_latency} columns={["median_ms", "p95_ms"]} />}
      >
        <TrendLine
          rows={data.door_latency}
          series={LATENCY_SERIES}
          label="Door latency per day"
          unit="ms"
        />
      </Figure>

      {/* 066a. `response_bytes` is on every admitted row and was aggregated nowhere,
          while `oversize` — which the figure above this pane already draws — is its
          symptom. A day whose oversize count rises is a day to read this beside it.

          Its own figure and **not a second axis on the latency chart**: two measures of
          different scale are two figures, which is `charts.tsx`' standing rule and the
          reason it has never had one.

          Absent where nothing reported a size, rather than drawn flat: a deployment
          brokering only tools that report none would get a chart of zeros inviting
          somebody to wonder what went wrong. */}
      {data.door_bytes.some((day) => day.bytes > 0) ? (
        <Figure
          title="How big a response was"
          lede={
            <>
              The 95th percentile of a single response, day by day — the number the
              response cap is set against, and the one the <em>too large</em> band in the
              numbers above is the tail of. The day&rsquo;s total is under{" "}
              <em>Show the numbers</em>: it is mostly a restatement of the traffic chart,
              because a busy day carries more bytes for the same reason it carries more
              calls.
            </>
          }
          series={BYTES_SERIES}
          table={<DayTable rows={data.door_bytes} columns={["bytes", "p95_bytes"]} />}
        >
          {/* **One series, not two, and this was two in the first build.** A day's total
              bytes runs to millions and a single response's p95 to thousands, so on one
              axis the p95 was a flat line along the floor — which is exactly the
              *"no second y-axis, at any callsite, ever; two measures of different scale
              are two figures"* rule that `charts.tsx` opens with, broken by the callsite
              rather than by the primitive.

              The resolution is not two figures but one: the total is the traffic chart
              multiplied by an average, and drawing it again says nothing the chart above
              does not. So the size of a response is the figure, and the total is a
              column in the table. Caught by looking at the rendered page. */}
          <TrendLine
            rows={data.door_bytes}
            series={BYTES_SERIES}
            label="Response bytes per day"
          />
        </Figure>
      ) : null}

      {/* 066b. The one figure here that reads a rhythm, and the only one on which a
          single hour of live traffic is visible beside a heavy month — which is the
          failure that prompted this step. Window-wide rather than per day, because
          *when is the door busy* is a question about the shape of a week. */}
      {data.hourly.length ? (
        <Figure
          title="When the door is busy"
          lede={
            <>
              Every call in this window, by hour of the day and day of the week, in UTC —
              the same clock the ceiling charges on, which is not anybody&rsquo;s local
              working day. A lit cell is traffic; an empty one is none, rather than the
              least of some.
            </>
          }
          total={`busiest hour: ${Math.max(
            ...data.hourly.map((cell) => cell.calls),
          ).toLocaleString()} calls`}
        >
          <Heat cells={data.hourly} label="Calls by weekday and hour" />
        </Figure>
      ) : null}

        <Card title="Busiest day against the ceiling">
          <Meter
            value={headroom.busiest_day_calls}
            of={headroom.metered ? headroom.ceiling : null}
            caption={
              headroom.metered ? (
                headroom.days_at_ceiling > 0 ? (
                  <>
                    Something ran out of allowance on {headroom.days_at_ceiling}{" "}
                    {headroom.days_at_ceiling === 1 ? "day" : "days"} in this window.
                  </>
                ) : (
                  <>Nothing hit the daily ceiling in this window.</>
                )
              ) : (
                <>
                  The daily ceiling is <strong>not enforced</strong> on this deployment,
                  so there is no limit to draw against — this is the observed volume
                  alone.
                </>
              )
            }
          />
        </Card>
    </>
  );

  const identityPane = (
    <>
      <Figure
        title="On whose behalf"
        lede={
          <>
            Of everything that went out under this workspace's credentials, how much was
            for a named person whose token we checked, how much on an application's word,
            and how much for nobody in particular. The three are never added together: an
            asserted name is worth what the calling app's honesty is worth.
          </>
        }
        total={`${pct(totals.door_verified, traffic)} verified`}
        series={IDENTITY_SERIES}
        table={<DayTable rows={data.identity} columns={["verified", "asserted", "none"]} />}
      >
        <BarStack
          rows={data.identity}
          series={IDENTITY_SERIES}
          label="Identity per day"
          // A band opens that day's calls made on that kind of claim — which is the
          // query an incident starts with and could not be put before 066.
          href={(row, s) =>
            toDoorLog(
              { since: bucketDay(row.day), until: bucketDay(row.day) },
              { identity_source: s.key },
            )
          }
        />
      </Figure>

      {/* 066a. The chart above counts three kinds of claim and **names nobody**, which
          leaves *on whose authority did this happen* unanswerable on the page built to
          answer it. This is the names.

          One row per (name, source) and never per name: 033c's rule one layer up — an
          asserted name is worth exactly what the calling application's honesty is worth,
          and a row that added a verified count to an asserted one would upgrade the
          claim in the one record kept to tell them apart. So a person reached both ways
          appears twice, deliberately, with the claim in the note. */}
      <Figure
        title="Whose names went out"
        lede={
          <>
            Who calls were made on behalf of, with what the claim was worth beside each.
            A person reached two ways is <strong>two rows</strong> — an asserted name and
            a verified one are not the same fact and are never added together. Calls
            naming nobody are the <em>nobody named</em> band above rather than a row here.
          </>
        }
        total={ofTotal(data.acting_for.length, data.acting_for_count, "name")}
      >
        {data.acting_for.length ? (
          <HBar
            rows={data.acting_for.map((row) => ({
              name: row.acting_for,
              value: row.calls,
              inset: row.denied || undefined,
              insetLabel: "refused",
              note: row.identity_source === "verified"
                ? "verified — their own token, checked"
                : "asserted — the calling app's word, unchecked",
              href: toDoorLog(win, {
                acting_for: row.acting_for,
                identity_source: row.identity_source,
              }),
              insetHref: toDoorLog(win, {
                acting_for: row.acting_for,
                identity_source: row.identity_source,
                decision: "deny",
              }),
            }))}
            tail={tailLine(
              data.acting_for_tail,
              "name",
              toDoorLog(win),
            )}
          />
        ) : (
          <Empty title="No call in this window named anybody" />
        )}
      </Figure>
    </>
  );

  const callersPane = (
    <>
      <Figure
        title="Who is calling"
        lede={
          <>
            The busiest callers this window, with the darker inset showing what each was
            refused. A person's several personal tokens are one caller here — the log
            records the principal, not the credential — and the tile above counts every
            caller, not just the ones named here.
          </>
        }
        // `ofTotal` rather than the tile's number alone. The list and the tile
        // disagreed by design and neither said so — the count was its own query
        // precisely *because* the list is capped, and nothing on the page ever
        // reconciled the two. Now one string carries both.
        total={ofTotal(data.callers.length, totals.callers, "caller")}
      >
        {data.callers.length ? (
          <HBar
            rows={data.callers.map((caller) => ({
              name: caller.principal_id,
              value: caller.calls,
              inset: caller.denied,
              insetLabel: "refused",
              // `principal_kind` has been on every one of these rows since 041 and the
              // page threw it away. A person and a machine are different readings of the
              // same bar — one is somebody's laptop, the other is a pipeline.
              note: `${caller.principal_kind} · ${caller.tools} ${caller.tools === 1 ? "tool" : "tools"} · last ${on(caller.last_seen)}`,
              href: toDoorLog(win, { principal_id: caller.principal_id }),
              insetHref: toDoorLog(win, {
                principal_id: caller.principal_id,
                decision: "deny",
              }),
            }))}
            tail={tailLine(data.caller_tail, "caller", toDoorLog(win))}
          />
        ) : (
          <Empty title="Nobody called through the door in this window" />
        )}
      </Figure>

      {/* 066a. **`CLAUDE.md`'s central noun, on this page for the first time.** An agent
          in Carnet is a named set of tools with a scope — the permission model itself,
          re-read on every single door call — and every audit row has carried the name
          since the table existed while no figure grouped by it.

          Here rather than in Governance because the question it completes is this pane's:
          *who is using this, and for what* is answered by who, under which grant, calling
          what. The grant is the middle term and it was missing. */}
      <Figure
        title="Under which permission list"
        lede={
          <>
            Which agent&rsquo;s grant admitted the traffic. An agent is a named set of
            tools with a scope — it is what a token is granted and how the door decides
            what an assistant may touch — so this is the same traffic as above, sorted by
            the permission that let it through. The count is tools actually{" "}
            <em>reached</em>, not tools granted: an agent carrying forty and calling two is
            worth knowing about.
          </>
        }
        total={ofTotal(data.door_agents.length, data.agent_count, "agent")}
      >
        {data.door_agents.length ? (
          <HBar
            rows={data.door_agents.map((row) => ({
              name: row.agent,
              value: row.calls,
              inset: row.denied || undefined,
              insetLabel: "refused",
              note: `${row.tools} ${row.tools === 1 ? "tool" : "tools"} reached`,
              href: toDoorLog(win, { agent: row.agent }),
              insetHref: toDoorLog(win, { agent: row.agent, decision: "deny" }),
            }))}
            tail={tailLine(data.agent_tail, "agent", toDoorLog(win))}
          />
        ) : (
          <Empty title="No agent's grant carried a call in this window" />
        )}
      </Figure>

      <Figure
        title="What is being called"
        lede={<>The busiest tools this window. The darker inset is what was refused.</>}
        total={ofTotal(data.door_tools.length, data.tool_count, "tool")}
      >
        {data.door_tools.length ? (
          <HBar
            rows={data.door_tools.map((tool) => ({
              name: tool.tool,
              value: tool.calls,
              inset: tool.denied,
              insetLabel: "refused",
              note: tool.effect === "write" ? "writes" : undefined,
              href: toDoorLog(win, { tool: tool.tool }),
              insetHref: toDoorLog(win, { tool: tool.tool, decision: "deny" }),
            }))}
            // The walkthrough's finding, closed: eighteen tools, a cap of fifteen, and a
            // tool that had just been called appearing nowhere with nothing admitting it.
            tail={tailLine(data.tool_tail, "tool", toDoorLog(win))}
          />
        ) : (
          <Empty title="No tool was called through the door in this window" />
        )}
      </Figure>

      {/* 066a. Latency existed per day and only per day, so *which tool is slow* — the
          first thing anybody asks after watching a p95 move — could not be asked here.

          Ranked by **how slow**, not by how busy: the busiest tool is the top row of the
          figure above, and repeating that order would draw the same chart twice.

          Capped with no tail, alone among the leaderboards, because a remainder would
          have to be a percentile of the tools below the cap and a median of medians is
          not a median. Said in the lede rather than left to be discovered. */}
      {data.tool_latency.length ? (
        <Figure
          title="Which tools are slow"
          lede={
            <>
              Median time per tool, slowest first — a different order from the figure
              above, which is busiest first. A tool that was only ever refused is absent
              rather than shown as instant: a refusal has no duration to report. Capped at
              fifteen with no remainder, because a percentile of everything below a cap is
              not a number.
            </>
          }
          total={`${data.tool_latency.length} timed`}
        >
          <HBar
            rows={data.tool_latency.map((row) => ({
              name: row.tool,
              value: row.median_ms ?? 0,
              note: `${row.calls.toLocaleString()} ${row.calls === 1 ? "call" : "calls"} · p95 ${
                row.p95_ms === null ? "—" : `${row.p95_ms.toLocaleString()}ms`
              }`,
              href: toDoorLog(win, { tool: row.tool }),
            }))}
            unit="ms"
          />
        </Figure>
      ) : null}
    </>
  );

      {/* The money, as a table rather than a figure. Two reasons, and the first is this
          page's own restraint: the question a reader brings is *what did this cost*, not
          *what is the trend*, and a five-cent day drawn as a column next to a fifty-dollar
          one is a chart that says nothing at either end. The second is that a dollar
          series would need its own axis formatting for values that span four orders of
          magnitude, which is a chart primitive nobody has needed yet.

          Absent entirely when nothing reported, which is every deployment brokering only
          ordinary tools — an empty money pane invites somebody to go looking for spend
          there is no such thing as. */}
  const costPane = (
    <>
        <Card title="What the door cost" hint="estimated, priced at read time">
          <p className="sentence">
            <strong>{money(totals.door_usd)}</strong> over {tokens(totals.door_tokens)},
            from the calls whose tool reported what it spent. Calls that touched no model
            are counted above and cost nothing here — the two figures are measured
            differently on purpose.
          </p>
          {totals.door_unpriced_models.length > 0 && (
            <p className="muted sentence">
              The figure <strong>excludes</strong>{" "}
              {totals.door_unpriced_models.join(", ")}, which the price list cannot value.
              Those tokens are in the total beside it and in nobody&rsquo;s dollars — a
              model with no rate is reported as unpriced rather than billed at some other
              model&rsquo;s. Adding{" "}
              {totals.door_unpriced_models.length === 1 ? "that id" : "those ids"} to the
              rate table at <code>CARNET_MODEL_RATES</code> prices{" "}
              {totals.door_unpriced_models.length === 1 ? "it" : "them"} here and
              everywhere else, including the day rows below — the history is repriced,
              never rewritten.
            </p>
          )}
          <DayTable rows={data.door_spend} columns={["usd", "tokens"]} />
          <p className="muted sentence">
            An estimate, not an invoice. Money is never stored — these are token counts
            priced at read time against the rate list in force, so correcting the list
            reprices the history.
          </p>
        </Card>
    </>
  );

  // Administrative change moves here from beside the ceiling meter. It sat there because
  // the two made a tidy pair on one row, not because they answer the same question:
  // *what did we refuse* and *who changed who may do what* are the two halves of the
  // governance question, and this is the first layout in which they can be adjacent
  // without one of them being three screens from the other.
  const governancePane = (
    <>
      <Figure
        title="What was refused, and by which control"
        lede={
          <>
            Five different facts, never added together. <em>Policy</em> is the broker
            saying no — the control working. <em>Door ceiling</em> is a credential past a
            daily allowance and <em>run budget</em> an agent past its own, which are sizing
            questions rather than security ones. <em>Access</em> is somebody refused a
            resource before any broker was reached. The door has two allowances — calls
            and money — and they stack as one band here and stand apart under{" "}
            <em>Show the numbers</em>, because they are answered differently: a call
            ceiling met is usually a loop, a spend ceiling met is a bill arriving.
          </>
        }
        total={`${totals.refusals.toLocaleString()} in this window`}
        series={REFUSAL_SERIES}
        table={
          <DayTable
            rows={data.refusals}
            columns={["policy", "ceiling", "door_spend", "run_budget", "access"]}
          />
        }
      >
        <BarStack
          rows={refusalBands(data.refusals)}
          series={REFUSAL_SERIES}
          label="Refusals per day"
          // **`access` goes to a different log, and that is the point of the branch.**
          // An access denial never reached a broker and has no `audit` row at all — it
          // is `access_denials`, a genuinely different table with its own reader. A link
          // that sent all four bands to the door's log would answer three of them and
          // quietly return nothing for the fourth.
          //
          // `run_budget` is unreachable from the door by construction — a door call has
          // no run and no `Budget` — so it goes nowhere rather than to a filter that can
          // only ever be empty.
          href={(row, s) => {
            const day = bucketDay(row.day);
            if (s.key === "access") return "/admin/denials";
            if (s.key === "run_budget") return undefined;
            return toDoorLog({ since: day, until: day }, { decision: "deny" });
          }}
        />
      </Figure>

      {/* 066a. The chart above says *which control* refused. This says **what it said**,
          which is the directly actionable half and the one the log has always held.

          It is also where the chart's own compromise is repaid: three of those five
          bands are recovered by matching sentences, because 033b kept one write path and
          a budget denial is not a distinct kind of row. The sentences are right here. */}
      {data.refusal_reasons.length ? (
        <Figure
          title="What the refusals actually said"
          lede={
            <>
              The sentences the controls wrote, ranked. The chart above says which control
              said no; this is what it told the caller. These are written by Carnet, not
              by whoever called — a refusal quotes no caller text back onto this page.
            </>
          }
          total={ofTotal(
            data.refusal_reasons.length,
            data.refusal_reason_count,
            "reason",
          )}
        >
          <HBar
            rows={data.refusal_reasons.map((row) => ({
              name: row.reason,
              value: row.count,
              // The reason is **not** a filter and the link does not pretend it is: it
              // is a whole sentence, and a URL carrying one would break the moment
              // somebody reworded a refusal. The row opens the window's refusals and the
              // reader reads the sentence there, where it is on the record beside the
              // call that got it.
              href: toDoorLog(win, { decision: "deny" }),
            }))}
            tail={tailLine(
              data.refusal_reason_tail,
              "reason",
              toDoorLog(win, { decision: "deny" }),
            )}
          />
        </Figure>
      ) : null}

        <Card title="Administrative change">
          {changes.length ? (
            <HBar rows={changes} />
          ) : (
            <Empty title="Nobody changed who may do what in this window" />
          )}
        </Card>
    </>
  );

  const tabs: Tab[] = [
    { id: "traffic", label: "Traffic", panel: trafficPane },
    { id: "identity", label: "Identity", panel: identityPane },
    { id: "callers", label: "Callers & tools", panel: callersPane },
    // Absent where nothing reported usage, for the reason the card was already absent
    // there: an empty money pane invites somebody to go looking for spend there is no
    // such thing as.
    ...(totals.door_tokens > 0
      ? [{ id: "cost", label: "Cost", panel: costPane }]
      : []),
    { id: "governance", label: "Governance", panel: governancePane },
  ];

  return (
    <>
      {win.clamped ? (
        <p className="muted sentence">
          That window is not one this page keeps, so it answered with the nearest —{" "}
          {win.days} days.
        </p>
      ) : null}

      {/* The tiles are the briefing, and 066 gives them the two things a briefing needs:
          **a comparison**, so a number can be sized, and **a way down**, so a reader who
          wants the calls behind one is not left copying it into a log by hand.

          Every delta is against the same-length window immediately before this one, and
          every one is rendered in ink — refusals falling and traffic falling are opposite
          news, and a coloured arrow would decide for the reader on half of them. */}
      <Stats
        items={[
          {
            k: "Calls through the door",
            v: traffic.toLocaleString(),
            delta: delta(traffic, before?.door_calls),
            href: toDoorLog(win),
          },
          {
            k: "Refused",
            v: `${totals.door_denied.toLocaleString()} · ${pct(totals.door_denied, traffic)}`,
            delta: delta(totals.door_denied, before?.door_denied),
            href: toDoorLog(win, { decision: "deny" }),
          },
          {
            k: "Writes",
            v: totals.door_writes.toLocaleString(),
            delta: delta(totals.door_writes, before?.door_writes),
            href: toDoorLog(win, { effect: "write" }),
          },
          {
            k: "On a verified identity",
            v: pct(totals.door_verified, traffic),
            alert: traffic > 0 && totals.door_verified / traffic < 0.5,
            // **In points, because the tile is a share.** `delta` would report the
            // movement of the count under a figure that is a percentage — two
            // percentages one line apart measuring different things, which reads as the
            // share having moved by the second one. See `shareDelta`.
            delta: shareDelta(
              totals.door_verified,
              traffic,
              before?.door_verified,
              before?.door_calls,
            ),
            href: toDoorLog(win, { identity_source: "verified" }),
          },
          {
            k: "Callers",
            v: totals.callers.toLocaleString(),
            delta: delta(totals.callers, before?.callers),
          },
          // What the door cost, beside what it carried. Step 045b, and it reads `—`
          // rather than `$0.00` when nothing reported: a brokered tool call whose token
          // cost is a vendor's problem is the ordinary case, and a confident zero would
          // say *this door is free* about a deployment nobody has metered.
          {
            k: "Door spend",
            v: totals.door_tokens > 0 ? money(totals.door_usd) : "—",
            delta:
              totals.door_tokens > 0
                ? delta(totals.door_tokens, before?.door_tokens)
                : null,
          },
        ]}
      />

      {traffic === 0 ? (
        <Card>
          <Empty title="No calls came through the door in this window">
            If people are connecting their assistants and you expected traffic, the door
            is where to look.
          </Empty>
        </Card>
      ) : null}

      {/* The tiles stay above the strip and the footnote below it. Both describe the
          whole page rather than any pane of it, and 041 built this so that *"a screenshot
          of its top is the briefing"* — a summary behind a tab is not a summary. */}
      <Tabs
        tabs={tabs}
        active={params.get("view") ?? tabs[0].id}
        onSelect={select}
        label="Overview sections"
      />

      <p className="muted sentence footnote">
        {/* The window's dates and never its bucket labels — with hour buckets those are
            `…T00` and `…T23`, and a footnote built from them would say "2026-08-31T00 to
            2026-08-31T23, in UTC days". The route sends dates for exactly this. */}
        {win.bucket === "hour" ? (
          <>
            {win.since}, by the hour, in UTC — the same day the door charges its ceiling
            against, which begins and ends at midnight UTC rather than at yours. All
            twenty-four hours are drawn, including the ones still ahead.
          </>
        ) : (
          <>
            {win.since} to {win.until}, in UTC days — the same day boundary the door
            charges its ceiling against.
          </>
        )}{" "}
        Figures cover this workspace only. Every bar, tile and row here opens the calls
        behind it in the door&rsquo;s log.
      </p>
    </>
  );
}

/** The numbers behind a figure. Every field the server sent, including the ones the
 *  chart folded together — `cancelled` and `interrupted` share a band above and have
 *  their own columns here, and the door's overlapping `errored`/`oversize` are shown as
 *  the server counts them rather than as the chart partitions them. */
function DayTable<T extends { day: string }>({
  rows,
  columns,
}: {
  rows: T[];
  columns: (keyof T & string)[];
}) {
  const shown = rows.filter((row) =>
    columns.some((column) => Number(row[column]) > 0),
  );
  if (!shown.length) return <Empty title="Nothing in this window" />;

  return (
    <table>
      <thead>
        <tr>
          <th>Day</th>
          {columns.map((column) => (
            <th key={column} className="num">
              {column.replace(/_/g, " ")}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {shown.map((row) => (
          <tr key={row.day}>
            <td className="mono">{row.day}</td>
            {columns.map((column) => (
              <td key={column} className="num">
                {/* **`null` is an em dash, never a zero**, and this table coerced it to
                    `0` until 066 gave it a nullable column to render. `Number(null)` is
                    `0`, so a day nothing was timed on reported a median of *0ms* — the
                    exact distinction `LatencyDay` exists to keep: *never ran*, not *ran
                    in no time*. The chart above has always drawn those days as gaps; the
                    table under it was filling them in.

                    Latent until now because every column this table had was a counter,
                    where 0 is the truth. `door_latency` and `p95_bytes` are the first
                    that can be absent. */}
                {row[column] === null || row[column] === undefined
                  ? "—"
                  : Number(row[column]).toLocaleString()}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
