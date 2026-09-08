/** Turning the API's values into something a person reads.
 *
 * Every timestamp arrives ISO-8601 and timezone-aware, and is rendered in the reader's
 * local zone. Nothing here parses a timestamp to compare it — ordering is the server's
 * job, and for a good reason: `created_at` turned out not to be a sortable key at all,
 * which is why `runs` grew a `seq` column. A client that re-sorts by a rendered time
 * would be reintroducing that bug one layer up.
 */

/** A clock time. `""` for a moment that has not happened, which the API says with `""`
 *  and this deliberately does not turn into "never" or "—" here: the caller decides
 *  what an absent moment looks like in its own sentence. */
export function at(iso: string): string {
  if (!iso) return "";
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return iso;
  return when.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** Date and time, for a list where runs may span days. */
export function on(iso: string): string {
  if (!iso) return "";
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return iso;
  const today = new Date();
  const sameDay =
    when.getFullYear() === today.getFullYear() &&
    when.getMonth() === today.getMonth() &&
    when.getDate() === today.getDate();
  return sameDay
    ? at(iso)
    : when.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
}

/** A calendar date **with its year**, for a fact that is not about today.
 *
 *  `on()` deliberately omits the year — it was written for run and log listings, where
 *  everything is recent and the year is noise. **That makes it the wrong formatter for an
 *  expiry**, which 035f found by rendering one: a credential that expired in 2020 and one
 *  expiring in 2099 both come out as `Dec 31` and `Mar 4`, so the reader takes a lapse
 *  five years old for one last December. On a screen about access that is not a cosmetic
 *  difference — it is the difference between *act now* and *nothing to do*.
 *
 *  No time of day, because these are answers to *when does this stop working* and the
 *  hour has never been the question. Rendered in the reader's own zone like every other
 *  instant here: an expiry is a real moment, so the day it falls on genuinely differs by
 *  where you are, and `inZone` exists for the opposite case — a *local-time claim* like a
 *  schedule, which this is not. */
export function day(iso: string): string {
  if (!iso) return "";
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return iso;
  return when.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

/** Whether an instant has already passed. `false` for anything unparseable, which is the
 *  quieter of the two wrong answers: a garbage stamp should not raise an alarm.
 *
 *  Safe as a client-side derivation for the reason `TokenMarks.State` gives — it is not a
 *  control, and the server refuses an expired credential whatever a page renders. **Not
 *  safe on every field**: see `ConnectionsPage.lapse`, where the same comparison on an
 *  OAuth access token would call most healthy connections expired. */
export function passed(iso: string): boolean {
  const when = new Date(iso).getTime();
  return !Number.isNaN(when) && when < Date.now();
}

export function ms(value: number): string {
  if (!value) return "0ms";
  return value < 1000 ? `${value}ms` : `${(value / 1000).toFixed(1)}s`;
}

/** A token count, at the precision a person compares two of them at. `1240000` -> `1.24M`.
 *
 *  Exact under a thousand and rounded above, for `bytes()`' reason one row down: nobody
 *  has ever needed the last digit of a nine-million-token total, and thirteen characters
 *  of it makes the numbers either side harder to read against.
 *
 *  **`0` renders as `—`, never as `0`.** A run whose tokens were never counted — one from
 *  before the counters existed, or one that never reached a model call — and a run that
 *  cost nothing are different facts, and only one of them is possible: no model reply is
 *  free. A literal zero on the page would assert the impossible one. */
export function tokens(value: number): string {
  if (!value) return "—";
  if (value < 1000) return String(value);
  if (value < 1_000_000) return `${(value / 1000).toFixed(1)}k`;
  return `${(value / 1_000_000).toFixed(2)}M`;
}

/** An estimated cost, in dollars. `—` for a figure nothing could be priced from.
 *
 *  **Never `$0.00` for an unpriced model**, which is the whole reason this is a function
 *  rather than a `toFixed`. Zero is a claim — *this cost nothing* — and the server hands
 *  back a figure that deliberately excludes models it has no rate for. Rendering that
 *  exclusion as zero would turn "we do not know" into "it was free", in the one direction
 *  a person reading a bill must not be misled.
 *
 *  Cents, because a day of one agent is single-digit dollars and rounding it to whole
 *  ones would show `$0` for a real morning's work. */
export function money(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `$${value.toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

export function bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} kB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

/** How long a run took, from two of its three moments. `""` while it is still going —
 *  a running total that ticks would be inventing precision the server never claimed. */
export function elapsed(started: string, finished: string): string {
  if (!started || !finished) return "";
  const a = new Date(started).getTime();
  const b = new Date(finished).getTime();
  if (Number.isNaN(a) || Number.isNaN(b) || b < a) return "";
  return ms(b - a);
}

/** An instant in a **named** zone, with the zone's own abbreviation beside it.
 *
 *  The one function here that does not render in the reader's zone, and the exception is
 *  the whole subject of it. A schedule is a *local-time* claim: somebody typed "every
 *  morning at 07:30" meaning 07:30 where they are, and the server stores the zone
 *  alongside because the instant alone cannot say that. Rendering a schedule's next fire
 *  in the reader's zone would show 06:30 to a colleague in London and quietly answer a
 *  question nobody asked.
 *
 *  `timeZoneName: "short"` is what stops the result being a different lie — "07:30" with
 *  no zone is indistinguishable from the reader's own clock, and it is exactly the
 *  ambiguity a person is trying to resolve when they look at this.
 *
 *  An unknown zone falls back to the reader's rather than throwing: a row whose zone this
 *  browser cannot load is a row somebody still needs to read and delete. */
export function inZone(iso: string, timeZone: string): string {
  if (!iso) return "";
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return iso;
  const options: Intl.DateTimeFormatOptions = {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  };
  try {
    return when.toLocaleString(undefined, { ...options, timeZone });
  } catch {
    return when.toLocaleString(undefined, options);
  }
}

/** The zone this browser believes it is in, for prefilling a field a person must confirm.
 *
 *  A **visible** prefill, never a silent default: the server refuses a schedule with no
 *  zone precisely because guessing wrong fires an agent at the wrong hour every day
 *  forever. A value somebody can read and change before they submit is a different thing
 *  from one chosen behind them. */
export function browserZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  } catch {
    return "";
  }
}

/** An answer that is a JSON **object**, indented. Anything else, byte for byte as it came.
 *
 *  Step 035i, closing the third clause of 024's register row: *"the run page renders the
 *  JSON answer as plain text in the Block."* An agent with an `output.schema` answers with
 *  a JSON document, and until this it arrived as whatever single line the model emitted —
 *  so the one feature whose whole purpose is a machine-readable answer produced the least
 *  readable thing on the page.
 *
 *  Three properties, each deliberate:
 *
 *  **It asks nobody whether the agent has a schema.** `RunDetail` does not carry the
 *  agent's config and must not grow a second request to answer a question about
 *  formatting. Whether an answer *is* structured is a property of the answer, and this is
 *  the only place that fact is needed.
 *
 *  **Object-rooted only**, which is the platform's own rule rather than a new one:
 *  `_validate_output_section` refuses a schema that is not rooted at an object, *"and a
 *  consumer of a bare string had no need of a schema"*. So an array, a number, `true` and
 *  a bare string are left exactly as they are — all four are valid JSON and none is what
 *  this exists for. That also all but removes the misfire: a prose answer reaches this
 *  branch only by being literally a JSON object, in which case indenting it is right.
 *
 *  **It never throws and never loses anything.** A parse failure returns the input, which
 *  is what every answer that is not JSON does, which is most of them. */
export function prettyIfJsonObject(answer: string): string {
  const trimmed = answer.trim();
  // Cheap gate before the parse, so the common case — prose, sometimes long — does not
  // hand a paragraph to `JSON.parse` on every render of every run.
  if (!trimmed.startsWith("{")) return answer;
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return answer;
    return JSON.stringify(parsed, null, 2);
  } catch {
    return answer;
  }
}
