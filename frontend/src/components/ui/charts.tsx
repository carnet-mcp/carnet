/** Three chart primitives, hand-written in SVG. Step 041b.
 *
 * This frontend has no charting dependency and has declined one more than once, for the
 * reason it declined a UI library and generated types: the hand-written version carries
 * its own reasoning and its own idiom, and a chart library brings a second design system
 * that has to be fought back to the token layer anyway. Three primitives at this size do
 * not move that line. A page that later needs brushing, zooming and thirty chart types
 * can reopen the question with requirements in hand.
 *
 * ## What they have in common, and why it is fixed here rather than per caller
 *
 * **The surface does the separating.** Every touching mark — each segment of a stack,
 * each adjacent column — is parted by a 2px gap in `--paper`, never by a stroke around
 * the mark. A border is ink that is not data. The gap is also the secondary encoding
 * the status stacks need: `--good` beside `--warn` is ΔE 6.8 under protanopia, legal in
 * that floor band only when something other than hue separates them.
 *
 * **Marks are thin and the chrome is recessive.** Columns cap at 24px and let the band's
 * leftover be air; lines are 2px; the grid is a hairline one step off the surface.
 *
 * **Colour never lands on text.** Marks carry the series colour; labels, values, axis
 * ticks and legend text wear ink tokens, and identity reaches the legend as a swatch
 * beside the words. A `--chart-4` label on `--paper` is unreadable, and the fix is not
 * a darker yellow.
 *
 * **Every mark carries a `<title>`.** That is the browser's own tooltip: hover, no
 * JavaScript, and it is what a screen reader reads for the mark. It is not a substitute
 * for the numbers — `Figure` puts those under a `<details>`, which is what discharges
 * the validator's light-mode contrast warning on `--chart-3` and `--chart-4`.
 *
 * **Nothing animates.** This page is read at a glance and screenshotted into a channel;
 * a transition is a thing that is wrong in the screenshot.
 *
 * **A mark may be a link, and that is the only interaction there is.** Step 066: the
 * Overview's aggregate and the door's log were two screens with no edge between them, so
 * every primitive here takes an optional `href` and wraps its marks in an `<a>` when one
 * is given. Nothing else changes - the mark keeps its `<title>`, an `<a>` around an SVG
 * shape is focusable and keyboard-reachable for free, and the only new CSS is a focus
 * ring and a cursor. A callsite that passes no `href` renders exactly what it rendered
 * before, down to the element tree.
 *
 * There is still no hover state, no active mark, no tooltip beyond the browser's own,
 * and no selection. A link is navigation, not a control, and the page it lives on says
 * of itself that nothing on it changes anything.
 *
 * ## What is deliberately absent
 *
 * No second y-axis, at any callsite, ever — two measures of different scale are two
 * figures. No pie. No colour scale computed from a value: a bar's length already encodes
 * its magnitude, and colouring it by the same number spends the identity channel saying
 * something twice.
 */

import type { ReactNode } from "react";
import { Link } from "react-router-dom";

// The plot box. One geometry for every figure here, so two charts stacked on a page
// have their baselines and left edges in the same place — which is most of what makes a
// dashboard look assembled rather than collected.
const W = 720;
const H = 180;
const PAD = { top: 8, right: 8, bottom: 22, left: 40 };
const PLOT = {
  w: W - PAD.left - PAD.right,
  h: H - PAD.top - PAD.bottom,
};

/** The 2px of surface that separates touching marks. Not a stroke — see the header. */
const GAP = 2;
/** Columns never fill their band; the leftover is the air between days. */
const MAX_BAR = 24;

export interface Series {
  /** The key on each row that carries this series' number. */
  key: string;
  /** What it is called, in the legend and in the tooltip. Sentence case. */
  label: string;
  /** A CSS colour — always a `var(--chart-*)`, never a literal. */
  color: string;
}

/** A tick scale that lands on numbers a person would have chosen: 1/2/5 × 10ⁿ.
 *
 * Rounding the top of the axis up to one of those is what keeps the gridlines at
 * readable values (0 / 50 / 100) instead of at whatever the maximum happened to be
 * divided by four. */
function niceCeiling(value: number): number {
  if (value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const scaled = value / magnitude;
  const step = scaled <= 1 ? 1 : scaled <= 2 ? 2 : scaled <= 5 ? 5 : 10;
  return step * magnitude;
}

function ticksFor(max: number): number[] {
  const top = niceCeiling(max);
  // **No fractional gridline on an axis of whole things.** Every series drawn here is a
  // count of calls, and `niceCeiling` bottoms out at 1 — so an empty or one-call window
  // drew ticks at 0, **0.5** and 1, offering to measure half a call.
  //
  // Always latent and reachable only on a quiet window; 066 made quiet windows ordinary
  // by adding a 24-hour view, where most hours are empty on most deployments and one of
  // them is often the whole chart.
  if (top < 2) return [0, top];
  return [0, top / 2, top].filter((value, index, all) => all.indexOf(value) === index);
}

/** Thousands-separated, which is the only number formatting any of these do. */
const num = (value: number) => value.toLocaleString();

/** A short day label — `28 Aug`. The full date lives in every mark's `<title>`, so the
 *  axis is free to be sparse. */
function dayLabel(day: string): string {
  // An hour bucket, step 066: `2026-08-31T14` reads as `14:00`. Told apart by the `T`
  // rather than by a flag threaded through four components — the two spellings are
  // different lengths and one contains a character the other cannot, so the value is
  // self-describing and a primitive never has to be told which window it is drawing.
  const [date, hour] = day.split("T");
  if (hour !== undefined) return `${hour}:00`;

  const [, month, dayOfMonth] = date.split("-");
  const names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${Number(dayOfMonth)} ${names[Number(month) - 1] ?? month}`;
}

/** How many day labels a 720-wide axis can hold without them touching. Chosen by
 *  width rather than by row count: thirty days and ninety days are the same axis, and
 *  only one of them can print every label. */
function labelEvery(count: number): number {
  return Math.max(1, Math.ceil(count / 10));
}

// --- the frame -----------------------------------------------------------------------

/** Gridlines, y ticks and the baseline. Recessive by construction — a hairline one step
 *  off the surface, and ink-faint text — because the data is the only thing on this page
 *  allowed to be loud. */
function Frame({ ticks, scale }: { ticks: number[]; scale: (v: number) => number }) {
  return (
    <g aria-hidden="true">
      {ticks.map((tick) => (
        <g key={tick}>
          <line
            className="chart-grid"
            x1={PAD.left}
            x2={PAD.left + PLOT.w}
            y1={scale(tick)}
            y2={scale(tick)}
          />
          <text className="chart-tick" x={PAD.left - 6} y={scale(tick)} dy="0.32em">
            {num(tick)}
          </text>
        </g>
      ))}
      <line
        className="chart-axis"
        x1={PAD.left}
        x2={PAD.left + PLOT.w}
        y1={scale(0)}
        y2={scale(0)}
      />
    </g>
  );
}

// --- BarStack ------------------------------------------------------------------------

/** A row is anything with a `day` and the series keys on it.
 *
 *  Generic rather than an index-signature interface, because the call sites pass real
 *  types — `DoorDay`, `RefusalDay`, `IdentityDay` — and an interface without an index
 *  signature is not assignable to one that has it. Widening those to
 *  `[key: string]: number` to satisfy a chart would delete the field names from the
 *  types that document the wire, which is backwards: the chart is generic, the data is
 *  not. `read` below is the one narrow cast that buys it. */
export interface StackRow {
  day: string;
}

/** One series' value on one row. The single place a `Series.key` meets a typed row. */
function read(row: StackRow, key: string): number | null {
  const value = (row as unknown as Record<string, unknown>)[key];
  return value === null || value === undefined ? null : Number(value);
}

/** Daily columns, stacked — part-to-whole over time.
 *
 * The series must be **disjoint and sum to the total**, which is a real constraint and
 * the one that is easy to get wrong: the door's `errored` and `oversize` are bands
 * *within* `allowed`, so stacking all four would draw a column taller than the traffic
 * it describes. `OverviewPage` derives a disjoint set before it gets here.
 *
 * Segments stack in array order, first at the baseline. That order is the caller's to
 * choose and it matters twice: it is what the eye compares against the axis (the bottom
 * segment is the only one with a straight edge to read), and it decides which pairs
 * touch — the only pairs whose colour separation has to hold. */
/** A mark, wrapped in a link when there is somewhere for it to go. Step 066.
 *
 *  One helper rather than a ternary at six call sites, because the failure it prevents is
 *  a mark that loses its `<title>` in one of the branches - the tooltip and the screen
 *  reader's text are the same attribute, so a branch that dropped it would be silently
 *  inaccessible rather than visibly broken.
 *
 *  **`Link`, never a bare `<a href>`, and this is not a style preference.** The first
 *  build used a plain anchor and every drill-down signed the reader out: `auth.ts` holds
 *  the access token in a **module-scope variable** — deliberately not `localStorage`, so
 *  that *"a machine left logged in overnight holds nothing"* — and a bare `<a>` is a full
 *  document navigation, which drops the module and therefore the token. The silent
 *  `prompt=none` re-auth then lands the reader on the target path having visibly bounced
 *  through a sign-in.
 *
 *  So every link this file emits is client-side. A page whose token cannot survive a
 *  reload is a page on which a full-page link is a bug, everywhere, forever.
 *
 *  Rendered inside an `<svg>` tree this is SVG's own anchor element — focusable,
 *  keyboard-reachable, and it takes the child's `<title>` as its accessible name. */
function Mark({ href, children }: { href?: string; children: ReactNode }) {
  if (!href) return <>{children}</>;
  return (
    <Link className="chart-link" to={href}>
      {children}
    </Link>
  );
}

export function BarStack<T extends StackRow>({
  rows,
  series,
  label,
  href,
}: {
  rows: readonly T[];
  series: Series[];
  label: string;
  /** Where a segment goes when it is clicked - the row and the series it belongs to,
   *  because a day's column and that day's *refused* band are two different queries and
   *  a caller has to be able to tell them apart. Return `undefined` for a segment that
   *  should stay inert. Step 066. */
  href?: (row: T, series: Series) => string | undefined;
}) {
  const totals = rows.map((row) =>
    series.reduce((sum, s) => sum + (read(row, s.key) ?? 0), 0),
  );
  const ticks = ticksFor(Math.max(...totals, 0));
  const top = ticks[ticks.length - 1];
  const scale = (value: number) => PAD.top + PLOT.h - (value / top) * PLOT.h;

  const band = PLOT.w / rows.length;
  const width = Math.min(MAX_BAR, band * 0.7);
  const every = labelEvery(rows.length);

  return (
    <svg
      className="chart"
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label={label}
      preserveAspectRatio="none"
    >
      <Frame ticks={ticks} scale={scale} />
      {rows.map((row, index) => {
        const x = PAD.left + band * index + (band - width) / 2;
        let cursor = 0;
        return (
          <g key={row.day}>
            {series.map((s) => {
              const value = read(row, s.key) ?? 0;
              if (value <= 0) return null;
              const y = scale(cursor + value);
              // The gap is taken off the *top* of every segment but the last, so the
              // stack's total height still reads against the axis.
              const height = Math.max(scale(cursor) - y - GAP, 1);
              cursor += value;
              return (
                <Mark key={s.key} href={href?.(row, s)}>
                  <rect
                    className="chart-mark"
                    x={x}
                    y={y}
                    width={width}
                    height={height}
                    fill={s.color}
                  >
                    <title>{`${row.day} · ${s.label}: ${num(value)}`}</title>
                  </rect>
                </Mark>
              );
            })}
            {index % every === 0 && (
              <text
                className="chart-tick"
                x={x + width / 2}
                y={PAD.top + PLOT.h + 14}
                textAnchor="middle"
              >
                {dayLabel(row.day)}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

// --- TrendLine -----------------------------------------------------------------------

/** One to three lines over the same days — the only form here that reads a *shape*
 *  rather than a magnitude.
 *
 *  A null is a **gap, never a zero**: a day nothing was timed on is not a day of instant
 *  calls, and joining across it would draw a slope that never happened. So each series
 *  is split into runs of consecutive present points, and a lone point between two nulls
 *  is drawn as a dot — otherwise a single measurement in a quiet week renders as
 *  nothing at all. */
export function TrendLine<T extends StackRow>({
  rows,
  series,
  label,
  unit = "",
}: {
  rows: readonly T[];
  series: Series[];
  label: string;
  unit?: string;
}) {
  const values = rows.flatMap((row) => series.map((s) => read(row, s.key)));
  const ticks = ticksFor(Math.max(...values.map((v) => v ?? 0), 0));
  const top = ticks[ticks.length - 1];
  const scale = (value: number) => PAD.top + PLOT.h - (value / top) * PLOT.h;

  const band = PLOT.w / rows.length;
  const at = (index: number) => PAD.left + band * index + band / 2;
  const every = labelEvery(rows.length);

  return (
    <svg
      className="chart"
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label={label}
      preserveAspectRatio="none"
    >
      <Frame ticks={ticks} scale={scale} />
      {series.map((s) => {
        const points = rows.map((row, index) => {
          const value = read(row, s.key);
          return value === null
            ? null
            : { x: at(index), y: scale(value), value, row, index };
        });

        // Runs of consecutive present points. A run of one becomes a dot below.
        const runs: { x: number; y: number; value: number; row: T; index: number }[][] =
          [];
        let run: typeof runs[number] = [];
        for (const point of points) {
          if (point) run.push(point);
          else if (run.length) {
            runs.push(run);
            run = [];
          }
        }
        if (run.length) runs.push(run);

        return (
          <g key={s.key}>
            {runs.map((segment, i) =>
              segment.length > 1 ? (
                <polyline
                  key={i}
                  className="chart-line"
                  points={segment.map((p) => `${p.x},${p.y}`).join(" ")}
                  stroke={s.color}
                />
              ) : (
                <circle
                  key={i}
                  className="chart-dot"
                  cx={segment[0].x}
                  cy={segment[0].y}
                  r={4}
                  fill={s.color}
                />
              ),
            )}
            {/* Hit targets. The line itself is 2px and hovering it is a game of
                precision; these are invisible, sized to the band, and carry the
                `<title>` for every point — including the ones drawn as part of a
                polyline, which has no per-point element of its own. */}
            {points.map((point) =>
              point ? (
                <circle
                  key={point.index}
                  className="chart-hit"
                  cx={point.x}
                  cy={point.y}
                  r={Math.max(8, band / 2)}
                >
                  <title>
                    {`${point.row.day} · ${s.label}: ${num(point.value)}${unit}`}
                  </title>
                </circle>
              ) : null,
            )}
          </g>
        );
      })}
      {rows.map((row, index) =>
        index % every === 0 ? (
          <text
            key={row.day}
            className="chart-tick"
            x={at(index)}
            y={PAD.top + PLOT.h + 14}
            textAnchor="middle"
          >
            {dayLabel(row.day)}
          </text>
        ) : null,
      )}
    </svg>
  );
}

// --- HBar ----------------------------------------------------------------------------

export interface HBarRow {
  name: string;
  value: number;
  /** The second number, drawn as a darker inset on the same bar — refusals inside a
   *  caller's traffic. Optional, and omitted rather than zero when there is none. */
  inset?: number;
  insetLabel?: string;
  note?: string;
  /** Where this row's calls are. Step 066 — the name becomes a link to the log filtered
   *  to it, which is the edge the Overview did not have. */
  href?: string;
  /** Where this row's **inset** is, which is a different query: a caller's traffic and a
   *  caller's refusals are two questions and the bar draws both. */
  insetHref?: string;
  /** A miniature of this row's shape over the window. Step 066b — a caller with 4,000
   *  calls on one day and one with 4,000 over a month are the same bar without it. */
  spark?: (number | null)[];
}

/** A ranked list with the magnitude drawn in — *who* and *what*, not *when*.
 *
 * **One hue for every bar**, and that is a rule rather than a default: these are nominal
 * categories (a caller is not more or less than another caller), so colouring them
 * individually would spend the identity channel re-encoding what bar length already
 * says. Rendered as an HTML list rather than SVG because the names are text of unknown
 * length — they wrap, they get ellipsised, they need a title attribute — and that is
 * what HTML is good at and SVG is not. */
export function HBar({
  rows,
  unit = "",
  tail,
}: {
  rows: HBarRow[];
  unit?: string;
  /** The rows this list does not show. Step 066.
   *
   *  Rendered as a **line under the bars and never as a bar**, which is the decision
   *  worth stating: the remainder is not one thing, and a bar labelled "3 more tools"
   *  invites the eye to compare it with the named ones as though it were. */
  tail?: ReactNode;
}) {
  const top = Math.max(...rows.map((row) => row.value), 1);

  return (
    <ul className="hbar">
      {rows.map((row, index) => (
        // **Indexed, not keyed on the name**, and 066 is what forced it: the acting-for
        // leaderboard has one row per *(name, identity source)* pair, so the same person
        // reached on their own token and on an application's word is two rows with one
        // name — which is 033c's rule and not a duplication to be tidied away.
        //
        // A ranked list is also positional by nature: it is re-sorted whole on every
        // render and nothing in it is edited in place, so the index is a stable identity
        // here in a way it is not in a list somebody types into. `DoorTrafficPage` keys
        // its log rows the same way for the same reason.
        <li key={index}>
          <span className="hbar-name" title={row.name}>
            {row.href ? <Link to={row.href}>{row.name}</Link> : row.name}
          </span>
          <span className="hbar-track">
            <span
              className="hbar-fill"
              style={{ width: `${(row.value / top) * 100}%` }}
            >
              {row.inset ? (
                <Mark href={row.insetHref}>
                  <span
                    className="hbar-inset"
                    style={{ width: `${(row.inset / row.value) * 100}%` }}
                    title={`${row.insetLabel ?? "of which"}: ${num(row.inset)}`}
                  />
                </Mark>
              ) : null}
            </span>
          </span>
          <span className="hbar-value">
            {num(row.value)}
            {unit}
          </span>
          {row.spark ? <Spark values={row.spark} label={row.name} /> : null}
          {row.note ? <span className="hbar-note">{row.note}</span> : null}
        </li>
      ))}
      {tail ? (
        <li className="hbar-tail">
          <span className="hbar-name">{tail}</span>
        </li>
      ) : null}
    </ul>
  );
}

// --- Spark ---------------------------------------------------------------------------

/** A leaderboard row's shape, at 48x14 with no axes. Step 066b.
 *
 *  **The smallest honest thing that can be added to a ranked list.** A caller with four
 *  thousand calls all on one Tuesday and a caller with four thousand spread evenly over
 *  a month draw the identical bar, and the two are not the same fact about a customer.
 *
 *  No axis, no ticks, no baseline and no numbers, which is what makes it a sparkline
 *  rather than a small chart: it says *what shape*, and the bar beside it already says
 *  *how much*. Scaled to its own maximum for the same reason — the comparison this
 *  offers is within a row, and one shared scale would flatten every row but the busiest
 *  into a straight line.
 *
 *  Nulls are gaps, `TrendLine`'s rule, and a single point becomes a dot. */
export function Spark({
  values,
  label,
}: {
  values: (number | null)[];
  label: string;
}) {
  const w = 48;
  const h = 14;
  const top = Math.max(...values.map((value) => value ?? 0), 1);
  const step = values.length > 1 ? w / (values.length - 1) : w;
  // 1px of padding top and bottom, so a maximum touches neither edge and a zero is
  // visibly on the floor rather than clipped against it.
  const y = (value: number) => h - 1 - (value / top) * (h - 2);

  const runs: string[][] = [];
  let run: string[] = [];
  values.forEach((value, index) => {
    if (value === null) {
      if (run.length) runs.push(run);
      run = [];
      return;
    }
    run.push(`${(index * step).toFixed(1)},${y(value).toFixed(1)}`);
  });
  if (run.length) runs.push(run);

  return (
    <svg
      className="spark"
      viewBox={`0 0 ${w} ${h}`}
      role="img"
      aria-label={`${label}: shape over the window`}
    >
      {runs.map((points, index) =>
        points.length > 1 ? (
          <polyline key={index} className="spark-line" points={points.join(" ")} />
        ) : (
          <circle
            key={index}
            className="spark-dot"
            cx={points[0].split(",")[0]}
            cy={points[0].split(",")[1]}
            r={1.2}
          />
        ),
      )}
    </svg>
  );
}

// --- Heat ----------------------------------------------------------------------------

const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/** Weekday x hour of day, as a grid of cells. Step 066b.
 *
 *  The one figure here that reads a **rhythm** rather than a magnitude or a trend, and
 *  the only one that survives the failure 066 exists to answer: eleven live calls in one
 *  hour is a lit cell whether or not the month behind it was heavy, where the same eleven
 *  calls as one column of a thirty-day chart are eleven pixels.
 *
 *  ## The ramp is sequential and it is in the token layer
 *
 *  Five steps of one hue, `--chart-heat-1` … `--chart-heat-5`, defined and validated in
 *  `tokens.css` beside the two ramps that were already there. Neither of those would do:
 *  `--chart-1..4` is categorical and colouring a magnitude with it says "these are four
 *  kinds of thing", and `--chart-step-1..3` is spoken for — it is the *identity* ordering,
 *  and a second meaning in one vocabulary is how a reader learns to distrust both.
 *
 *  An opacity ramp computed here was the cheap alternative and is refused on this file's
 *  own rule: a literal is *"a colour nobody checked"*, and a colour composited at runtime
 *  is a colour nobody checked either. The token layer is where light and dark are decided.
 *
 *  ## An empty cell is not the bottom of the ramp
 *
 *  A weekday-hour nothing happened in draws `--sunk`, not `--chart-heat-1`. *Nothing
 *  happened* and *the least that happened* are different facts — `LatencyDay`'s null
 *  rather than zero, in a grid — and on a quiet deployment almost every cell is the first
 *  of the two.
 *
 *  Quintiles of the maximum rather than of the distribution, because a reader compares a
 *  cell against the busiest hour, which is the number the legend names. */
export function Heat({
  cells,
  label,
}: {
  /** Sparse: only the weekday-hours that had traffic. */
  cells: { weekday: number; hour: number; calls: number }[];
  label: string;
  }) {
  const byKey = new Map(cells.map((cell) => [`${cell.weekday}:${cell.hour}`, cell.calls]));
  const busiest = Math.max(...cells.map((cell) => cell.calls), 0);

  const level = (calls: number) =>
    // 1..5 by fifths of the busiest cell. `ceil` so that any non-zero count lands on at
    // least the first step — a cell with one call in a week of thousands must still be
    // visible, because "somebody called at 3am on Sunday" is exactly the observation this
    // grid is for.
    Math.min(5, Math.max(1, Math.ceil((calls / busiest) * 5)));

  return (
    <div className="heat" role="img" aria-label={label}>
      <div className="heat-hours" aria-hidden="true">
        {[0, 6, 12, 18].map((hour) => (
          <span key={hour} style={{ gridColumnStart: hour + 2 }}>
            {String(hour).padStart(2, "0")}
          </span>
        ))}
      </div>
      {WEEKDAYS.map((name, weekday) => (
        <div className="heat-row" key={name}>
          <span className="heat-day" aria-hidden="true">
            {name}
          </span>
          {Array.from({ length: 24 }, (_, hour) => {
            const calls = byKey.get(`${weekday}:${hour}`) ?? 0;
            const reading = `${name} ${String(hour).padStart(2, "0")}:00 — ${num(calls)} ${
              calls === 1 ? "call" : "calls"
            }`;
            return (
              // **`title` the attribute, not `<title>` the element.** The first build
              // used the element, copying the SVG primitives above where it is correct —
              // and this grid is HTML, where `<title>` is a `<head>` element and renders
              // no tooltip at all. Every cell's count was unreachable: the figure said
              // *when* and could not be asked *how many*, which is half of what a heat
              // map is for, and it looked completely fine.
              //
              // `aria-label` beside it because a `title` attribute is not reliably
              // announced, and the count is the content here rather than a decoration.
              <span
                key={hour}
                className="heat-cell"
                title={reading}
                aria-label={reading}
                style={
                  calls
                    ? { background: `var(--chart-heat-${level(calls)})` }
                    : undefined
                }
              />
            );
          })}
        </div>
      ))}
    </div>
  );
}

// --- Meter ---------------------------------------------------------------------------

/** One number against one limit. Not a chart and deliberately not drawn as one — a
 *  single ratio is a meter, and a two-slice pie of the same fact is the anti-pattern.
 *
 *  `of` is null when the limit is not being enforced, and then this renders the figure
 *  with no track at all rather than a bar at 0%. A gauge against a ceiling nobody is
 *  counting is the most confident possible rendering of a number that does not exist. */
export function Meter({
  value,
  of,
  caption,
}: {
  value: number;
  of: number | null;
  caption: ReactNode;
}) {
  const ratio = of ? Math.min(value / of, 1) : 0;
  const tone = ratio >= 0.9 ? "bad" : ratio >= 0.7 ? "warn" : "ok";

  return (
    <div className="meter">
      <p className="meter-figure">
        <strong>{num(value)}</strong>
        {of ? <span className="muted"> of {num(of)}</span> : null}
      </p>
      {of ? (
        <span className="meter-track" role="img" aria-label={`${value} of ${of}`}>
          <span className={`meter-fill ${tone}`} style={{ width: `${ratio * 100}%` }} />
        </span>
      ) : null}
      <p className="meter-caption muted">{caption}</p>
    </div>
  );
}

// --- Figure --------------------------------------------------------------------------

/** A chart with everything that makes it readable: a title, a legend, and the numbers.
 *
 * **The legend is always present for two or more series** and never for one — with one
 * colour the heading already says what is plotted, and a box with a single swatch
 * restates it. Identity is a swatch *beside* ink-coloured text, never coloured text.
 *
 * **The numbers ride under a `<details>`**, closed by default. Two things need them.
 * `--chart-3` and `--chart-4` sit under 3:1 against white, which the validator passes
 * only where the values are legible some other way; and a manager reading this page
 * usually wants one exact figure out of it to paste into a message. A `<details>` costs
 * a line of markup, needs no JavaScript, is keyboard-reachable, and prints open. */
export function Figure({
  title,
  lede,
  series,
  total,
  children,
  table,
}: {
  title: string;
  lede?: ReactNode;
  series?: Series[];
  total?: ReactNode;
  children: ReactNode;
  table?: ReactNode;
}) {
  return (
    <figure className="figure">
      <figcaption>
        <span className="figure-title">{title}</span>
        {total ? <span className="figure-total">{total}</span> : null}
        {lede ? <span className="figure-lede muted">{lede}</span> : null}
      </figcaption>

      {series && series.length > 1 ? (
        <ul className="legend">
          {series.map((s) => (
            <li key={s.key}>
              <span className="swatch" style={{ background: s.color }} aria-hidden="true" />
              {s.label}
            </li>
          ))}
        </ul>
      ) : null}

      <div className="figure-plot">{children}</div>

      {table ? (
        <details className="figure-numbers">
          <summary>Show the numbers</summary>
          <div className="scroll-x">{table}</div>
        </details>
      ) : null}
    </figure>
  );
}
