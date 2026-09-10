/** The overview page, tested at the two places it can be confidently wrong.
 *
 * Most of this screen is figures, and a figure that rendered is not worth an assertion.
 * What is:
 *
 *   - **the door stack must be a partition.** `errored` and `oversize` are bands
 *     *within* `allowed`, so stacking the four fields as the wire sends them draws a
 *     column taller than the traffic it describes. The subtraction that fixes it lives
 *     on this page, which makes it this page's to prove — and the failure is invisible,
 *     because an over-tall bar still looks like a bar.
 *   - **the three identity sources stay three things**, for the reason
 *     `DoorTrafficPage` asserts it one screen over: a page that folded `asserted` into
 *     `verified` would not be losing a detail, it would be *upgrading an unverified
 *     claim* on the one chart built to tell them apart.
 *
 * Then the two states that decide whether the page is honest when there is nothing to
 * say: a tenant that uses only the door and a
 * deployment running unmetered (a gauge against a ceiling nobody counts is worse than
 * no gauge).
 */

import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return { ...actual, api: { overview: vi.fn() } };
});

import OverviewPage, { readWindow } from "./OverviewPage";
import { MeContext } from "../../lib/me";
import { api, ApiError } from "../../lib/api";
import type { Overview } from "../../lib/types";

const DAY = "2026-08-27";

/** A leaderboard that cut nothing. Step 066 — `n: 0` rather than an absent field, so a
 *  fixture never has to say "and there was no truncation" in three places. */
const NO_TAIL = { n: 0, calls: 0, denied: 0 };

function overview(patch: Partial<Overview> = {}): Overview {
  return {
    window: {
      days: 30,
      since: "2026-07-29",
      until: DAY,
      clamped: false,
      bucket: "day",
    },
    previous: null,
    totals: {
      door_calls: 0,
      door_denied: 0,
      door_writes: 0,
      door_verified: 0,
      callers: 0,
      refusals: 0,
      admin_changes: 0,
      door_usd: 0,
      door_tokens: 0,
      door_unpriced_models: [],
    },
    door_calls: [],
    door_spend: [],
    door_effects: [],
    identity: [],
    door_latency: [],
    door_bytes: [],
    callers: [],
    door_tools: [],
    // Step 066. `NO_TAIL` on the fixture so a test that does not care about truncation
    // says nothing about it, and a test that does sets exactly the tail it is testing.
    caller_tail: NO_TAIL,
    tool_count: 0,
    tool_tail: NO_TAIL,
    door_agents: [],
    agent_count: 0,
    agent_tail: NO_TAIL,
    acting_for: [],
    acting_for_count: 0,
    acting_for_tail: NO_TAIL,
    refusal_reasons: [],
    refusal_reason_count: 0,
    refusal_reason_tail: NO_TAIL,
    tool_latency: [],
    hourly: [],
    headroom: {
      metered: true,
      ceiling: 1000,
      busiest_day_calls: 0,
      days_at_ceiling: 0,
    },
    refusals: [],
    admin_actions: [],
    ...patch,
  };
}

/** Reports the query string, so a test can assert that a tab is *addressable* rather
 *  than merely selected — which is the whole reason 048 put the tab in the URL. */
function Where() {
  return <span data-testid="search">{useLocation().search}</span>;
}

const draw = (at = "/overview") =>
  render(
    <MeContext.Provider
      value={{
        me: {
          principal: "user:u_1",
          kind: "user",
          email: "a@b.c",
          display_name: "A",
          admin: true,
        },
        settled: true,
      }}
    >
      <MemoryRouter initialEntries={[at]}>
        <OverviewPage />
        <Where />
      </MemoryRouter>
    </MeContext.Provider>,
  );

/** Every mark title inside the figure with this accessible label. */
function marks(label: string): string[] {
  const svg = document.querySelector(`svg[aria-label="${label}"]`);
  return [...(svg?.querySelectorAll("title") ?? [])].map((t) => t.textContent ?? "");
}

/** The title of the figure called `name`. A figure's title is a `<span>` rather than a
 *  heading, and several now share their one word with a tile or a tab — "Callers",
 *  "Tools", "Agents" — so a bare text query would be ambiguous. */
const figureTitle = (name: string) =>
  screen.findByText(name, { selector: ".figure-title" });

/** The tile labelled `label`, for the same reason: "Spend" and "Requests" are also the
 *  cost card's heading and a figure's first word. */
const tile = async (label: string) =>
  (await screen.findByText(label, { selector: ".stat .k" })).closest(".stat") as HTMLElement;

beforeEach(() => {
  vi.mocked(api.overview).mockReset();
});

describe("the requests stack", () => {
  it("subtracts the bands that live inside `allowed`, so the column is the traffic", async () => {
    // 10 admitted, of which 2 errored and 1 was too large, plus 3 refused. The day's
    // traffic is 13 — and a naive stack of the four wire fields would draw 16.
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, door_calls: 13, door_denied: 3 },
        door_calls: [
          { day: DAY, allowed: 10, denied: 3, errored: 2, oversize: 1 , ok: 0, unknown: 0 },
        ],
      }),
    );

    draw();
    expect(await screen.findByText("13")).toBeInTheDocument();

    const drawn = marks("Requests per day");
    expect(drawn).toEqual([
      `${DAY} · Allowed: 10`,
      `${DAY} · Denied: 3`,
    ]);

    // The two segments sum to the traffic and no more. The trap: `errored` and
    // `oversize` are *inside* `allowed`, so a stack that also drew them would total 16
    // for a day on which 13 calls arrived — and an over-tall bar still looks like a bar.
    const total = drawn.reduce((sum, t) => sum + Number(t.split(": ")[1]), 0);
    expect(total).toBe(13);
  });

  it("keeps the outcome bands out of the stack and in the numbers", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, door_calls: 13, door_denied: 3 },
        door_calls: [{ day: DAY, allowed: 10, denied: 3, errored: 2, oversize: 1 , ok: 0, unknown: 0 }],
      }),
    );

    draw();
    await figureTitle("Requests per day");

    // Not a segment...
    expect(marks("Requests per day").some((t) => t.includes("Errored"))).toBe(false);
    // ...but not lost either: the rate is on the figure, and the count is in the table.
    expect(screen.getByText(/15% errored/)).toBeInTheDocument();
  });

  it("draws no denied segment on a day nothing was denied", async () => {
    // A zero drawn as a hairline reads as a small amount of something, on a day that
    // had none of it — and on this figure that something is "the broker turned people
    // away", which is not a thing to imply by accident.
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, door_calls: 9 },
        door_calls: [
          { day: "2026-08-26", allowed: 4, denied: 2, errored: 0, oversize: 0 , ok: 0, unknown: 0 },
          { day: DAY, allowed: 3, denied: 0, errored: 0, oversize: 0 , ok: 0, unknown: 0 },
        ],
      }),
    );

    draw();
    await figureTitle("Requests per day");

    expect(marks("Requests per day")).toEqual([
      "2026-08-26 · Allowed: 4",
      "2026-08-26 · Denied: 2",
      `${DAY} · Allowed: 3`,
    ]);
  });
});

describe("the identity split", () => {
  it("keeps verified, asserted and nobody-named as three separate counts", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, door_calls: 6, door_verified: 3 },
        identity: [{ day: DAY, verified: 3, asserted: 2, none: 1 }],
      }),
    );

    draw();
    await screen.findByText("On whose behalf");

    expect(marks("Identity per day")).toEqual([
      `${DAY} · Verified: 3`,
      `${DAY} · Asserted: 2`,
      `${DAY} · Nobody named: 1`,
    ]);
  });

  it("flags a window where most calls carried no checked identity", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, door_calls: 10, door_verified: 2 },
        identity: [{ day: DAY, verified: 2, asserted: 0, none: 8 }],
      }),
    );

    draw();

    const verified = await tile("Verified identity");
    expect(verified).toHaveClass("alert");
    expect(within(verified).getByText("20%")).toBeInTheDocument();
  });
});

describe("headroom", () => {
  it("draws no gauge when no rate limit is set, and says so", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, door_calls: 400 },
        headroom: {
          metered: false,
          ceiling: 0,
          busiest_day_calls: 400,
          days_at_ceiling: 0,
        },
      }),
    );

    draw();
    await screen.findByText("Busiest day against the rate limit");

    expect(document.querySelector(".meter-track")).toBeNull();
    expect(screen.getByText(/No rate limit is set/)).toBeInTheDocument();
  });

  it("reports the days the rate limit was reached", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        headroom: {
          metered: true,
          ceiling: 1000,
          busiest_day_calls: 990,
          days_at_ceiling: 3,
        },
      }),
    );

    draw();

    expect(
      await screen.findByText(/The rate limit was reached on 3 days/),
    ).toBeInTheDocument();
    expect(document.querySelector(".meter-fill")).toHaveClass("bad");
  });
});

describe("what the requests cost, step 045b", () => {
  const spending = () =>
    overview({
      totals: {
        ...overview().totals,
        door_calls: 4,
        door_usd: 30,
        door_tokens: 2_000_000,
      },
      door_calls: [{ day: DAY, allowed: 4, denied: 0, errored: 0, oversize: 0 , ok: 0, unknown: 0 }],
      door_spend: [{ day: DAY, usd: 30, tokens: 2_000_000, unpriced_models: [] }],
    });

  it("puts the money beside the traffic on the tile row", async () => {
    vi.mocked(api.overview).mockResolvedValue(spending());

    draw();

    const spend = await tile("Spend");
    expect(within(spend).getByText("$30.00")).toBeInTheDocument();
  });

  it("reads a dash rather than $0.00 when nothing reported what it spent", async () => {
    // Which is every deployment brokering ordinary tools, whose token cost is a vendor's
    // problem. A confident zero would say *this door is free* about one nobody metered.
    vi.mocked(api.overview).mockResolvedValue(
      overview({ totals: { ...overview().totals, door_calls: 9 } }),
    );

    draw();

    const spend = await tile("Spend");
    expect(within(spend).getByText("—")).toBeInTheDocument();
  });

  it("draws no money pane at all when nothing reported", async () => {
    // An empty money pane invites somebody to go looking for spend there is no such thing
    // as.
    vi.mocked(api.overview).mockResolvedValue(
      overview({ totals: { ...overview().totals, door_calls: 9 } }),
    );

    draw();
    await figureTitle("Requests per day");

    // `hidden: true`, because the panes are hidden rather than unmounted — the assertion
    // is that the card was never drawn, not merely that it is behind another tab.
    expect(
      screen.queryByRole("heading", { name: "Spend", hidden: true }),
    ).not.toBeInTheDocument();
  });

  it("says the two figures are measured differently, because they are", async () => {
    vi.mocked(api.overview).mockResolvedValue(spending());

    draw();

    expect(
      await screen.findByRole("heading", { name: "Spend", hidden: true }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Calls that used no model cost nothing here/),
    ).toBeInTheDocument();
  });

  it("names the models the price list could not value", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: {
          ...overview().totals,
          door_calls: 2,
          door_usd: 0,
          door_tokens: 1_000_000,
          door_unpriced_models: ["llama-3-70b"],
        },
        door_spend: [
          { day: DAY, usd: 0, tokens: 1_000_000, unpriced_models: ["llama-3-70b"] },
        ],
      }),
    );

    draw();

    expect(await screen.findByText(/llama-3-70b/)).toBeInTheDocument();
    expect(screen.getByText(/no rate in the price list/)).toBeInTheDocument();
    // Step 045c decision 4: the operator reading this screen is the person who can
    // close the gap, so the sentence names the file rather than only the shortfall.
    expect(screen.getByText(/CARNET_MODEL_RATES/)).toBeInTheDocument();
  });

  it("calls the figure an estimate and says money is never stored", async () => {
    vi.mocked(api.overview).mockResolvedValue(spending());

    draw();

    expect(
      await screen.findByText(/An estimate, not an invoice/),
    ).toBeInTheDocument();
  });
});

describe("the denial bands", () => {
  const refused = (patch = {}) => ({
    day: DAY,
    policy: 0,
    ceiling: 0,
    door_spend: 0,
    run_budget: 0,
    access: 0,
    ...patch,
  });

  it("stacks the two rate limits as one band and keeps them apart in the numbers", async () => {
    // The token layer's own rule: a fifth categorical series is a fold, never a generated
    // fifth hue. What is lost is telling them apart by eye; what is kept is a stack that
    // still sums to the day's refusals.
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, refusals: 5 },
        refusals: [refused({ ceiling: 2, door_spend: 3 })],
      }),
    );

    draw();
    await figureTitle("Denials by control");

    // Drawn as one segment of five, so the stack still reaches the day's total.
    expect(
      document.querySelector('[aria-label="Denials per day"] title'),
    ).toHaveTextContent("Rate limit: 5");

    // And told apart under *Show the numbers*, where the difference is actionable. The
    // table is in the document whether or not the `<details>` is open — the disclosure is
    // presentation, not a fetch — so this asserts the column exists rather than driving
    // a click that would test `<details>` instead of the page.
    const numbers = within(
      screen.getByText("Denials by control", { selector: ".figure-title" }).closest("figure")!,
    );
    expect(numbers.getByText("spend limit")).toBeInTheDocument();
    expect(numbers.getByText("rate limit")).toBeInTheDocument();
  });

  it("says the two rate limits are one band on the chart and separate in the numbers", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({ refusals: [refused({ door_spend: 1 })] }),
    );

    draw();

    expect(
      await screen.findByText(/the two are one band here and separate under/),
    ).toBeInTheDocument();
  });
});

describe("a workspace that only uses the MCP server", () => {
  it("shows its traffic", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, door_calls: 5, callers: 1 },
        door_calls: [{ day: DAY, allowed: 5, denied: 0, errored: 0, oversize: 0 , ok: 0, unknown: 0 }],
        callers: [
          {
            principal_kind: "machine",
            principal_id: "tok_alice",
            owner: "",
            calls: 5,
            denied: 0,
            writes: 1,
            tools: 2,
            last_seen: "2026-08-27T09:00:00.000+00:00",
          },
        ],
      }),
    );

    draw();

    expect(await screen.findByText("tok_alice")).toBeInTheDocument();
  });

  it("says so when nothing came through at all", async () => {
    vi.mocked(api.overview).mockResolvedValue(overview());

    draw();

    expect(
      await screen.findByText("No requests in this window"),
    ).toBeInTheDocument();
  });
});

// --- step 066: the road from a number to its calls -----------------------------------
//
// The walkthrough's second finding: no bar, tile or row linked to anything, so the
// aggregate and the record were two screens with no edge between them. Every assertion
// here is about that edge, and each one names the query it should carry — a link that
// went to the log with no filters would look right and answer a different question.

/** The `href` of the link wrapping the mark whose `<title>` contains `text`. */
function linkFor(label: string, text: string): string | null {
  const svg = document.querySelector(`svg[aria-label="${label}"]`);
  for (const title of svg?.querySelectorAll("title") ?? []) {
    if (title.textContent?.includes(text)) {
      return title.closest("a")?.getAttribute("href") ?? null;
    }
  }
  return null;
}

describe("every number points at its calls", () => {
  it("sends a day's column to that day, and its denied band to that day's denials", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, door_calls: 13, door_denied: 3 },
        door_calls: [
          { day: DAY, allowed: 10, denied: 3, errored: 0, oversize: 0, ok: 10, unknown: 0 },
        ],
      }),
    );

    draw();
    await figureTitle("Requests per day");

    // The column: that day, everything.
    expect(linkFor("Requests per day", "Allowed")).toBe(
      `/admin/door-calls?since=${DAY}&until=${DAY}`,
    );
    // The band: that day, refusals. A different question, so a different query — a link
    // that sent both to the same place would answer one of them wrongly.
    expect(linkFor("Requests per day", "Denied")).toBe(
      `/admin/door-calls?since=${DAY}&until=${DAY}&decision=deny`,
    );
  });

  it("navigates without reloading, because a reload signs the reader out", async () => {
    // **The bug this pins, found by clicking a bar in a real browser.** Every link here
    // was a bare `<a href>`, which is a full document navigation — and `auth.ts` holds
    // the access token in a *module-scope variable*, deliberately not `localStorage`, so
    // that "a machine left logged in overnight holds nothing". A full navigation drops
    // the module, drops the token, and the reader is bounced through a sign-in on their
    // way to a page they were already entitled to see.
    //
    // Asserted structurally rather than by driving a router: react-router's `Link`
    // renders an anchor that handles its own click, and jsdom cannot show the difference
    // between a reload and a push. What it *can* show is that no link on this page is
    // outside a router's control — which is the property, and which a bare `<a>` breaks.
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, door_calls: 13, door_denied: 3 },
        door_calls: [
          { day: DAY, allowed: 10, denied: 3, errored: 0, oversize: 0, ok: 10, unknown: 0 },
        ],
        callers: [
          {
            principal_kind: "machine",
            principal_id: "tok_hot",
            owner: "",
            calls: 40,
            denied: 2,
            writes: 1,
            tools: 3,
            last_seen: `${DAY}T09:00:00.000+00:00`,
          },
        ],
        caller_tail: { n: 4, calls: 90, denied: 0 },
      }),
    );

    draw("/overview?view=callers");
    await figureTitle("Callers");

    // Every internal link is relative — a `Link` renders its `to` verbatim for an
    // in-app path, and nothing on this page should be pointing at an absolute URL or
    // carrying a target that would leave the SPA.
    const links = [...document.querySelectorAll("a[href]")];
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) {
      expect(link.getAttribute("href")).toMatch(/^\//);
      expect(link.getAttribute("target")).toBeNull();
    }
  });

  it("labels a person's pooled personal tokens with their email and links the log by it", async () => {
    // Step 108. The log's rows still name the machine, so a link filtered by the
    // owner's id would find nothing; the bar links by the email instead.
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        callers: [
          {
            principal_kind: "user",
            principal_id: "u_priya",
            owner: "priya@example.com",
            calls: 12,
            denied: 1,
            writes: 0,
            tools: 2,
            last_seen: `${DAY}T09:00:00.000+00:00`,
          },
          {
            principal_kind: "machine",
            principal_id: "tok_nightly",
            owner: "",
            calls: 3,
            denied: 0,
            writes: 0,
            tools: 1,
            last_seen: `${DAY}T09:00:00.000+00:00`,
          },
        ],
      }),
    );

    draw("/overview?view=callers");
    await figureTitle("Callers");

    const person = (await screen.findByText("priya@example.com")).closest("a")!;
    expect(person.getAttribute("href")).toContain("owner=priya%40example.com");
    expect(person.getAttribute("href")).not.toContain("principal_id");
    const bot = screen.getByText("tok_nightly").closest("a")!;
    expect(bot.getAttribute("href")).toContain("principal_id=tok_nightly");
  });

  it("sends an access denial to the other log, because it is a different table", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        refusals: [
          {
            day: DAY,
            policy: 1,
            ceiling: 0,
            door_spend: 0,
            run_budget: 0,
            access: 2,
          },
        ],
      }),
    );

    draw("/overview?view=governance");
    await figureTitle("Denials by control");

    // An access denial never reached a broker and has **no audit row at all**. A link
    // that sent it to the door's log would return nothing and read as "there were none",
    // which is the one wrong answer available here.
    expect(linkFor("Denials per day", "Access")).toBe("/admin/denials");
    expect(linkFor("Denials per day", "Policy")).toBe(
      `/admin/door-calls?since=${DAY}&until=${DAY}&decision=deny`,
    );
  });

  it("carries the window into every link, so a drill-down does not silently widen", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        callers: [
          {
            principal_kind: "machine",
            principal_id: "tok_hot",
            owner: "",
            calls: 40,
            denied: 2,
            writes: 1,
            tools: 3,
            last_seen: `${DAY}T09:00:00.000+00:00`,
          },
        ],
      }),
    );

    draw("/overview?view=callers");
    const link = await screen.findByRole("link", { name: "tok_hot" });

    // The window's own dates, not the log's default page — a reader who narrowed to a
    // week and then clicked through must not land on thirty days of rows.
    expect(link.getAttribute("href")).toBe(
      "/admin/door-calls?since=2026-07-29&until=2026-08-27&principal_id=tok_hot",
    );
  });

  it("makes a tile a link and gives it the window before this one", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, door_calls: 120 },
        previous: { ...overview().totals, door_calls: 100 },
      }),
    );

    draw();
    await screen.findByText("120");

    expect(screen.getByText("+20% on the window before")).toBeInTheDocument();
  });

  it("says so in words rather than dividing by a window of zero", async () => {
    // "up ∞%" is what the arithmetic produces and it is not a thing to print. The
    // previous window has traffic here — it is the *tile's own* figure that was zero.
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, door_calls: 40, door_writes: 5 },
        previous: { ...overview().totals, door_calls: 30, door_writes: 0 },
      }),
    );

    draw();
    await screen.findByText("40");

    expect(screen.getByText("none in the window before")).toBeInTheDocument();
  });

  it("drops every comparison when there was no previous window to compare with", async () => {
    // Found by looking at the rendered page: on a deployment younger than its own
    // window, six tiles each read "none in the window before" — one fact about the
    // deployment dressed as six facts about the figures.
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, door_calls: 40, door_writes: 5 },
        previous: { ...overview().totals, door_calls: 0 },
      }),
    );

    draw();
    await screen.findByText("40");

    expect(screen.queryByText(/window before/)).not.toBeInTheDocument();
  });

  it("shows no comparison at all when the server sent none", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({ totals: { ...overview().totals, door_calls: 40 } }),
    );

    draw();
    await screen.findByText("40");

    expect(screen.queryByText(/on the window before/)).not.toBeInTheDocument();
  });
});

// --- step 066: a cap that says what it cut -------------------------------------------

describe("a truncated leaderboard admits it", () => {
  it("names the total beside the list and links to the rows it cut", async () => {
    // The walkthrough's first finding: eighteen tools, a cap of fifteen, and a tool that
    // had just been called appearing nowhere with nothing on the page saying so.
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        door_tools: [
          { tool: "search_issues", effect: "read", calls: 90, denied: 0 },
        ],
        tool_count: 18,
        tool_tail: { n: 3, calls: 412, denied: 7 },
      }),
    );

    draw("/overview?view=callers");
    await figureTitle("Tools");

    expect(screen.getByText("top 1 of 18 tools")).toBeInTheDocument();
    expect(screen.getByText(/3 more tools/)).toBeInTheDocument();
    expect(screen.getByText(/412 calls between them/)).toBeInTheDocument();
    // And what the remainder was denied, because "412 more calls" while hiding that
    // seven were denied would be worse than saying nothing.
    expect(screen.getByText(/7 denied/)).toBeInTheDocument();
  });

  it("says nothing about truncation when nothing was truncated", async () => {
    // Five figures each carrying a permanent "and no more" is noise on every page.
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        door_tools: [{ tool: "search_issues", effect: "read", calls: 90, denied: 0 }],
        tool_count: 1,
      }),
    );

    draw("/overview?view=callers");
    await figureTitle("Tools");

    expect(screen.getByText("1 tool")).toBeInTheDocument();
    expect(screen.queryByText(/not shown/)).not.toBeInTheDocument();
  });

  it("reconciles the caller tile with the caller list instead of leaving them to disagree", async () => {
    // The count was its own query *because* the list is capped, and nothing on the page
    // ever said so — the tile read 5,214 and the list drew fifteen bars.
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, callers: 5214 },
        callers: [
          {
            principal_kind: "machine",
            principal_id: "tok_1",
            owner: "",
            calls: 40,
            denied: 0,
            writes: 0,
            tools: 1,
            last_seen: `${DAY}T09:00:00.000+00:00`,
          },
        ],
        caller_tail: { n: 5213, calls: 900, denied: 0 },
      }),
    );

    draw("/overview?view=callers");

    expect(await screen.findByText("top 1 of 5,214 callers")).toBeInTheDocument();
  });
});

// --- step 066a: the dimensions the page threw away -----------------------------------

describe("the three dimensions every row carried", () => {
  it("groups by the permission list, which is what an agent is", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        door_agents: [{ agent: "issue-reporter", calls: 40, denied: 2, tools: 3 }],
        agent_count: 1,
      }),
    );

    draw("/overview?view=callers");
    await figureTitle("Agents");

    expect(screen.getByText("3 tools used")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "issue-reporter" }).getAttribute("href"),
    ).toContain("agent=issue-reporter");
  });

  it("never adds a verified name to an asserted one", async () => {
    // 033c's rule one layer up. The same person reached two ways is two rows, because a
    // row that summed them would upgrade the weaker claim.
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        acting_for: [
          { acting_for: "sam@x.com", identity_source: "verified", calls: 9, denied: 0 },
          { acting_for: "sam@x.com", identity_source: "asserted", calls: 4, denied: 0 },
        ],
        acting_for_count: 2,
      }),
    );

    draw("/overview?view=identity");
    await figureTitle("Names");

    expect(screen.getAllByRole("link", { name: "sam@x.com" })).toHaveLength(2);
    expect(screen.getByText(/their own token, checked/)).toBeInTheDocument();
    expect(screen.getByText(/the calling app's word, unchecked/)).toBeInTheDocument();
  });

  it("ranks what the denials said, and does not put a sentence in a URL", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        refusal_reasons: [{ reason: "tool not granted to this token", count: 12 }],
        refusal_reason_count: 1,
      }),
    );

    draw("/overview?view=governance");
    await figureTitle("Denial reasons");

    const link = screen.getByRole("link", { name: "tool not granted to this token" });
    // The reason is a whole sentence and a URL carrying one would break the moment
    // somebody reworded a refusal. The row opens the window's refusals instead.
    expect(link.getAttribute("href")).toBe(
      "/admin/door-calls?since=2026-07-29&until=2026-08-27&decision=deny",
    );
  });

  it("draws the hour grid and leaves a quiet hour empty rather than faint", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({ hourly: [{ weekday: 0, hour: 14, calls: 6 }] }),
    );

    draw();
    await figureTitle("Busy hours");

    const grid = screen.getByRole("img", { name: "Calls by weekday and hour" });
    // 7 days x 24 hours, drawn whole — a sparse response is not a sparse grid.
    expect(grid.querySelectorAll(".heat-cell")).toHaveLength(168);
    // *Nothing happened* and *the least that happened* are different facts, so only the
    // one cell with traffic carries a ramp colour.
    expect(
      [...grid.querySelectorAll<HTMLElement>(".heat-cell")].filter((cell) =>
        cell.style.background.includes("chart-heat"),
      ),
    ).toHaveLength(1);
  });
});

// --- step 066: the edge pass -----------------------------------------------------------
//
// Five defects found after the step was "done" — three by looking at the rendered page,
// one by clicking it, one by probing the route. Each is pinned here because each was
// invisible in a passing test suite.

describe("the edge pass", () => {
  it("refuses a window the route would 422 on, rather than rendering a fault", () => {
    // With `days` in the URL this is one keystroke away, and the rule this step wrote
    // for `?view=` applies: a URL somebody mistyped should show them the page, not a
    // fault. `GET /admin/overview` declares `ge=1, le=3650`.
    expect(readWindow("5000")).toBe(30);
    expect(readWindow("0")).toBe(30);
    expect(readWindow("-3")).toBe(30);
    expect(readWindow("abc")).toBe(30);
    expect(readWindow(null)).toBe(30);
    expect(readWindow("")).toBe(30);
    // Not rounded into something the route accepts — `7.5` is a 422 at the route, and a
    // client that quietly made it 7 would draw a window nobody asked for.
    expect(readWindow("7.5")).toBe(30);
    expect(readWindow("7abc")).toBe(30);
  });

  it("passes through a window the route accepts but does not offer, so the clamp can speak", () => {
    // 45 is not one of the four buttons. The server answers with the nearest and says
    // `clamped`, which the page prints — clamping here as well would silence that
    // sentence and let the page draw a month while claiming six weeks.
    expect(readWindow("45")).toBe(45);
    expect(readWindow("1")).toBe(1);
    expect(readWindow("90")).toBe(90);
  });

  it("prints an em dash where a percentile is absent, never a zero", async () => {
    // `Number(null)` is 0, so a nullable column read as *0* — the distinction
    // `LatencyDay` exists to keep: never ran, not ran in no time.
    //
    // **The case has to be a mixed row**, which writing the first version of this test
    // established: `DayTable` already drops a row whose every column is falsy, so a day
    // with no measurement at all never reaches the renderer and the chart's gap is the
    // only thing that describes it. What reaches it is a row with one real number and
    // one absent — and that is why this fixture is bytes rather than latency, where the
    // median and the percentile are computed over one set and are always both or
    // neither.
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        door_bytes: [
          { day: "2026-08-26", bytes: 4000, p95_bytes: 900 },
          { day: DAY, bytes: 400, p95_bytes: null },
        ],
      }),
    );

    draw();
    const figure = await figureTitle("Response size");
    const details = figure.closest(".figure")!.querySelector("details")!;
    details.setAttribute("open", "");

    const cells = [...details.querySelectorAll("td")].map((c) => c.textContent);
    expect(cells).toContain("—");
    expect(cells).not.toContain("0");
    // And the numbers that are there still read as themselves.
    expect(cells).toContain("400");
    expect(cells).toContain("900");
  });

  it("gives the heat grid a real tooltip, which an HTML <title> child is not", async () => {
    // The first build copied the SVG primitives' `<title>` element into an HTML grid,
    // where `<title>` is a `<head>` element and renders nothing. Every cell's count was
    // unreachable and the figure looked completely fine.
    vi.mocked(api.overview).mockResolvedValue(
      overview({ hourly: [{ weekday: 0, hour: 14, calls: 6 }] }),
    );

    draw();
    await figureTitle("Busy hours");

    const lit = [...document.querySelectorAll<HTMLElement>(".heat-cell")].find((cell) =>
      cell.style.background.includes("chart-heat"),
    )!;
    expect(lit.getAttribute("title")).toBe("Mon 14:00 — 6 calls");
    expect(lit.querySelector("title")).toBeNull();
  });

  it("moves a share in points, because the tile it sits under is a percentage", async () => {
    // 54% over "+12% on the window before" is two percentages a line apart measuring
    // different things, and the natural reading is that the share moved by the second.
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        totals: { ...overview().totals, door_calls: 100, door_verified: 54 },
        previous: { ...overview().totals, door_calls: 100, door_verified: 40 },
      }),
    );

    draw();
    await screen.findByText("54%");

    expect(screen.getByText("+14 points on the window before")).toBeInTheDocument();
  });

  it("never labels a full leaderboard with a total smaller than itself", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        door_tools: [
          { tool: "a", effect: "read", calls: 9, denied: 0 },
          { tool: "b", effect: "read", calls: 4, denied: 0 },
        ],
        tool_count: 0,
      }),
    );

    draw("/overview?view=callers");
    await figureTitle("Tools");

    expect(screen.getByText("2 tools")).toBeInTheDocument();
    expect(screen.queryByText("0 tools")).not.toBeInTheDocument();
  });
});

describe("the window", () => {
  it("says when the server answered a different one than was asked for", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({
        window: {
          days: 90,
          since: "2026-05-30",
          until: DAY,
          clamped: true,
          bucket: "day",
        },
      }),
    );

    draw();

    expect(await screen.findByText(/so the nearest was used/)).toBeInTheDocument();
  });

  it("stays quiet when it answered exactly what was asked", async () => {
    vi.mocked(api.overview).mockResolvedValue(overview());

    draw();
    await figureTitle("Requests per day");

    expect(screen.queryByText(/the nearest was used/)).toBeNull();
  });
});

describe("without the role", () => {
  it("carries the server's own sentence rather than a blank page", async () => {
    vi.mocked(api.overview).mockRejectedValue(
      new ApiError(403, "this needs the admin role, which you do not hold"),
    );

    draw();

    expect(
      await screen.findByText(/needs the admin role/),
    ).toBeInTheDocument();
  });
});


describe("the tabs are a URL, step 048", () => {
  // The constraint this whole step had to satisfy. `/admin/*` has sections rather than
  // tabs *"because an administrator sends these links to each other"*, and this page has
  // its own route *"because this is what gets sent to a manager."* Tabs that lived in
  // component state would quietly take that away, and nothing about the rendered page
  // would look wrong — which is exactly why it is asserted here.

  it("opens on the pane the URL names", async () => {
    vi.mocked(api.overview).mockResolvedValue(
      overview({ totals: { ...overview().totals, door_tokens: 900, door_usd: 1.25 } }),
    );

    draw("/overview?view=cost");

    // `getByRole` consults the accessibility tree, so a `hidden` pane cannot answer —
    // which is what makes this an assertion about what a reader can *see* rather than
    // about what React mounted.
    expect(
      await screen.findByRole("heading", { name: "Spend" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("img", { name: "Requests per day" }),
    ).not.toBeInTheDocument();
  });

  it("falls back to the first pane when the URL names one that does not exist", async () => {
    // The value arrives off a URL somebody can mistype or send from a build where the
    // pane had a different name. A blank page is a worse answer than the front of it.
    vi.mocked(api.overview).mockResolvedValue(overview());

    draw("/overview?view=nonsense");

    expect(
      await screen.findByRole("img", { name: "Requests per day" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Traffic" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });

  it("puts the chosen pane in the URL, so the link a manager is sent still opens on it", async () => {
    vi.mocked(api.overview).mockResolvedValue(overview());

    draw();
    fireEvent.click(await screen.findByRole("tab", { name: "Governance" }));

    expect(screen.getByTestId("search").textContent).toBe("?view=governance");
    expect(
      screen.getByRole("img", { name: "Denials per day" }),
    ).toBeInTheDocument();
  });

  it("keeps the tiles out of the tabs", async () => {
    // 041 built this page so that *"a screenshot of its top is the briefing"*. A summary
    // that hides behind a tab is not a summary, so the tiles answer on every pane.
    vi.mocked(api.overview).mockResolvedValue(overview());

    draw("/overview?view=identity");

    expect(await tile("Requests")).toBeInTheDocument();
    expect(await tile("Verified identity")).toBeInTheDocument();
  });

  it("offers no cost pane where nothing reported what it spent", async () => {
    // The card was already absent there, for the reason the pane is: an empty money pane
    // invites somebody to go looking for spend there is no such thing as.
    vi.mocked(api.overview).mockResolvedValue(overview());

    draw();

    expect(await screen.findByRole("tab", { name: "Traffic" })).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Cost" })).not.toBeInTheDocument();
  });

  it("moves between panes with the arrow keys", async () => {
    // One tab stop for the strip and arrows within it — the ARIA pattern for a tab set
    // whose panes are already loaded.
    vi.mocked(api.overview).mockResolvedValue(overview());

    draw();
    const traffic = await screen.findByRole("tab", { name: "Traffic" });
    fireEvent.keyDown(traffic, { key: "ArrowRight" });

    expect(screen.getByRole("tab", { name: "Identity" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    // Wraps, so the strip has no dead end.
    fireEvent.keyDown(screen.getByRole("tab", { name: "Identity" }), { key: "ArrowLeft" });
    fireEvent.keyDown(screen.getByRole("tab", { name: "Traffic" }), { key: "ArrowLeft" });
    expect(screen.getByRole("tab", { name: "Governance" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });
});
