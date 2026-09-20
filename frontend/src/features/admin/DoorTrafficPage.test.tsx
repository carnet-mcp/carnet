/** The Door traffic page, and the one thing it must not get wrong.
 *
 * It renders a log, so most of it is a table — and a table is not what is worth
 * asserting. What is:
 *
 *   - **the three identity sources stay three things.** This is the whole reason 033c
 *     stored `verified`, `asserted` and `none` instead of a boolean, and this screen is
 *     where that decision either survives or quietly dies. A page that rendered an
 *     asserted name the way it renders a verified one would not be losing a detail; it
 *     would be *upgrading an unverified claim* in the one record kept to tell them apart
 *   - **the 403 is the server's own sentence**, because somebody who deep-links here
 *     without the role must be told something they can act on
 *   - **a denial's reason is rendered**, since a page about what came through the door
 *     that cannot say why a call was refused is half a page
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return { ...actual, api: { adminDoorCalls: vi.fn() } };
});

import DoorTrafficPage from "./DoorTrafficPage";
import { api, ApiError } from "../../lib/api";
import type { DoorCallRecord } from "../../lib/types";

// Each fixture row gets its own sequence number, as the store gives one: the key a
// row is rendered by and the cursor a page turns (110f).
let seq = 0;

function record(overrides: Partial<DoorCallRecord> = {}): DoorCallRecord {
  return {
    id: ++seq,
    v: 7,
    ts: "2026-08-09T10:15:00+00:00",
    run_id: "door-0123456789ab",
    principal_kind: "machine",
    principal_id: "tok_9311cad7",
    owner: "",
    agent: "triage",
    tool: "acme_list_issues",
    effect: "read",
    decision: "allow",
    reason: "",
    outcome: "ok",
    duration_ms: 42,
    response_bytes: 147,
    acting_for: null,
    identity_source: "none",
    ...overrides,
  };
}

function show(rows: DoorCallRecord[], at = "/admin/door-calls") {
  vi.mocked(api.adminDoorCalls).mockResolvedValue(rows);
  return render(
    <MemoryRouter initialEntries={[at]}>
      <DoorTrafficPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(api.adminDoorCalls).mockReset();
});

describe("the log", () => {
  it("renders what was called, by whom, and under which agent's grant", async () => {
    show([record()]);

    expect(await screen.findByText("acme_list_issues")).toBeInTheDocument();
    expect(screen.getByText("triage")).toBeInTheDocument();
    expect(screen.getByText("tok_9311cad7")).toBeInTheDocument();
    expect(screen.getByText("allow")).toBeInTheDocument();
  });

  it("names the person behind a personal token, with the machine beneath", async () => {
    // Step 108, decision 5: the one question a customer opens this page with. A service
    // token has no person and keeps showing its id alone.
    show([record({ owner: "priya@example.com" }), record({ principal_id: "tok_bot", owner: "" })]);

    expect(await screen.findByText("priya@example.com")).toBeInTheDocument();
    expect(screen.getByText("tok_9311cad7")).toBeInTheDocument();
    expect(screen.getByText("tok_bot")).toBeInTheDocument();
    expect(screen.getByText("Called by")).toBeInTheDocument();
  });

  it("reads an owner filter from the URL, says it in words, and sends it", async () => {
    show([record({ owner: "priya@example.com" })], "/admin/door-calls?owner=priya%40example.com");

    expect(await screen.findByText(/Only calls by priya@example.com/)).toBeInTheDocument();
    expect(vi.mocked(api.adminDoorCalls)).toHaveBeenCalledWith(
      expect.objectContaining({ owner: "priya@example.com" }),
    );
  });

  it("says so when no request has come through the MCP server yet", async () => {
    show([]);

    expect(await screen.findByText("No requests yet")).toBeInTheDocument();
  });

  it("counts what is on screen and offers older rows after a full page", async () => {
    // A hundred rows is a page, not a window (110f): the count is the count, and
    // *Show older* is the way to the rest. "Matching" since 066, because the page
    // filters: a hundred under a filter is a hundred of the match.
    show(
      Array.from({ length: 101 }, (_, i) =>
        record({ run_id: `door-${String(i).padStart(12, "0")}` }),
      ),
    );

    expect(await screen.findByText("100 matching requests")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Show older" })).toBeInTheDocument();
    expect(screen.queryByText(/older records are not shown/)).toBeNull();
  });

  it("offers nothing older when the match ends exactly on a page boundary", async () => {
    show(
      Array.from({ length: 100 }, (_, i) =>
        record({ run_id: `door-${String(i).padStart(12, "0")}` }),
      ),
    );

    expect(await screen.findByText("100 matching requests")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Show older" })).toBeNull();
  });

  it("asks for the rows before the oldest shown, under the same filters", async () => {
    const first = Array.from({ length: 101 }, (_, i) => record({ id: 900 - i }));
    vi.mocked(api.adminDoorCalls)
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce([record({ id: 3, tool: "acme_create_issue" })]);
    render(
      <MemoryRouter initialEntries={["/admin/door-calls?agent=triage"]}>
        <DoorTrafficPage />
      </MemoryRouter>,
    );

    await userEvent.click(await screen.findByRole("button", { name: "Show older" }));

    expect(await screen.findByText("acme_create_issue")).toBeInTheDocument();
    expect(api.adminDoorCalls).toHaveBeenLastCalledWith(
      expect.objectContaining({ before: 801, limit: 101, agent: "triage" }),
    );
    expect(screen.queryByRole("button", { name: "Show older" })).toBeNull();
  });

  it("titles a partial page as a plain count, which it honestly is", async () => {
    show([record(), record({ run_id: "door-ffffffffffff" })]);

    expect(await screen.findByText("2 matching requests")).toBeInTheDocument();
  });

  it("links the agent and the token to their pages, and makes the tool a filter", async () => {
    // 110f, plan 107 D10. An agent and a token have pages; a tool has none, so its name
    // narrows the log instead — the denials page's own idiom.
    show([record({ owner: "priya@example.com" })]);

    expect(await screen.findByRole("link", { name: "triage" })).toHaveAttribute(
      "href",
      "/agents/triage",
    );
    expect(screen.getByRole("link", { name: "tok_9311cad7" })).toHaveAttribute(
      "href",
      "/tokens/tok_9311cad7",
    );
    await userEvent.click(screen.getByRole("button", { name: "acme_list_issues" }));
    expect(await screen.findByText(/Only calls to acme_list_issues/)).toBeInTheDocument();
  });

  it("asks for the log once and does not poll it", async () => {
    show([record()]);
    await screen.findByText("acme_list_issues");

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(api.adminDoorCalls).toHaveBeenCalledTimes(1);
  });
});

describe("the three identity sources", () => {
  it("keeps a verified name and an asserted one visibly apart", async () => {
    // The assertion this whole page exists to make. Both rows name Tom; only one of
    // them checked. If these ever render the same, the screen is lying about the
    // difference the log went to trouble to keep.
    show([
      record({ acting_for: "tom@acme.com", identity_source: "verified" }),
      record({ acting_for: "tom@acme.com", identity_source: "asserted" }),
    ]);

    const rows = await screen.findAllByRole("row");
    // Row 0 is the header.
    expect(within(rows[1]).getByText("verified")).toBeInTheDocument();
    expect(within(rows[2]).getByText("asserted")).toBeInTheDocument();

    // Never colour alone: both words are in the document as words, so a reader who
    // cannot distinguish the two tones keeps the distinction anyway.
    expect(screen.getByText("verified")).toBeInTheDocument();
    expect(screen.getByText("asserted")).toBeInTheDocument();
  });

  it("renders 'nobody named' rather than an empty cell", async () => {
    // `none` is an answer, not missing data. A blank cell here reads as a field the
    // server failed to send.
    show([record({ acting_for: null, identity_source: "none" })]);

    expect(await screen.findByText("nobody named")).toBeInTheDocument();
  });

  it("does not print a badge that contradicts a missing name", async () => {
    show([record({ acting_for: null, identity_source: "none" })]);

    await screen.findByText("nobody named");
    expect(screen.queryByText("verified")).not.toBeInTheDocument();
    expect(screen.queryByText("asserted")).not.toBeInTheDocument();
  });

  it("drives off identity_source rather than guessing from the name", async () => {
    // The defensive half: the source is written on every record and the name is not,
    // so a renderer that inferred one from the other would be guessing at exactly the
    // distinction the field exists to remove.
    show([record({ acting_for: "tom@acme.com", identity_source: "asserted" })]);

    expect(await screen.findByText("asserted")).toBeInTheDocument();
    expect(screen.queryByText("nobody named")).not.toBeInTheDocument();
  });
});

describe("a refused call", () => {
  it("renders the broker's own sentence rather than just 'deny'", async () => {
    const reason =
      "github.repo 'torvalds/linux' is outside this agent's 'read' scope.";
    show([record({ decision: "deny", outcome: "", duration_ms: null, reason })]);

    expect(await screen.findByText("deny")).toBeInTheDocument();
    expect(screen.getByText(reason)).toBeInTheDocument();
  });

  it("marks the one outcome that needs a person", async () => {
    // `unknown` means a write reached an external system and never answered. It may or
    // may not have taken effect, and this record is the only place that will ever say
    // so — printing it beside `ok` as another normal ending would bury that.
    show([record({ effect: "write", decision: "allow", outcome: "unknown" })]);

    expect(await screen.findByText("unknown")).toBeInTheDocument();
  });
});

describe("somebody who is not an administrator", () => {
  it("is shown the server's own sentence rather than a blank page", async () => {
    vi.mocked(api.adminDoorCalls).mockRejectedValue(
      new ApiError(
        403,
        "this needs an administrator of this workspace, and you are not one. Whoever runs your workspace can grant it.",
      ),
    );

    render(
      <MemoryRouter>
        <DoorTrafficPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText(/you are not one/)).toBeInTheDocument();
    expect(screen.getByText(/Signing in again will not change this/)).toBeInTheDocument();
  });

  it("does not render the table at all", async () => {
    vi.mocked(api.adminDoorCalls).mockRejectedValue(
      new ApiError(403, "not an administrator"),
    );

    render(
      <MemoryRouter>
        <DoorTrafficPage />
      </MemoryRouter>,
    );

    await screen.findByText(/not an administrator/);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });
});

describe("the table's width", () => {
  it("scrolls inside its own card rather than pushing the page sideways", async () => {
    // Eight columns of mono identifiers plus a failure sentence do not fit a narrow
    // window, and the page scrolling sideways moves the navigation off screen to read a
    // log. jsdom does no layout, so what is asserted is the *mechanism* — the table sits
    // in an `overflow-x` container — with the measurement itself done in a browser.
    vi.mocked(api.adminDoorCalls).mockResolvedValue([record()]);

    const { container } = render(
      <MemoryRouter>
        <DoorTrafficPage />
      </MemoryRouter>,
    );

    const table = await screen.findByRole("table");
    expect(table.closest(".scroll-x")).not.toBeNull();
    expect(container.querySelector(".scroll-x")).not.toBeNull();
  });
});


// --- step 066: the filters, and why they live in the URL ------------------------------
//
// `DenialsPage` keeps its filters in React state, and `DEFERRED.md` recorded why and what
// would change it: `Failure` titled every 422 "This agent's configuration is not valid",
// so a URL one keystroke from `?decision=banana` would answer a typo with a sentence
// about a different noun — *"the fix is `Failure`'s, and it is worth doing before the
// second log screen wants the same thing."* This is the second log screen; 066 retitled
// the 422 and put the filters where a link can carry them.

describe("the filters come from the URL", () => {
  it("forwards every filter in the query string to the server", async () => {
    show(
      [record()],
      "/admin/door-calls?since=2026-08-01&until=2026-08-09&tool=acme_list_issues" +
        "&agent=triage&principal_id=tok_9311cad7&decision=allow&effect=read",
    );
    await screen.findByText("acme_list_issues");

    // **The server filters, not this page.** A client narrowing a page it was already
    // given is a lie about completeness in a log view, which is `/admin/denials`' own
    // argument for pushing `resource_kind` to the route.
    expect(api.adminDoorCalls).toHaveBeenCalledWith(
      expect.objectContaining({
        since: "2026-08-01",
        until: "2026-08-09",
        tool: "acme_list_issues",
        agent: "triage",
        principalId: "tok_9311cad7",
        decision: "allow",
        effect: "read",
      }),
    );
  });

  it("asks for the calls nothing was recorded for, which is a real question", async () => {
    // `outcome` is `NOT NULL DEFAULT ''`, so the empty string is a stored value and a
    // truthiness check on the way through would silently turn this into "do not narrow"
    // and answer with the whole log.
    show([record()], "/admin/door-calls?outcome=");
    await screen.findByText("acme_list_issues");

    expect(api.adminDoorCalls).toHaveBeenCalledWith(
      expect.objectContaining({ outcome: "" }),
    );
  });

  it("names each narrowing with its value, so a link can be checked against it", async () => {
    show([record()], "/admin/door-calls?tool=acme_list_issues&decision=deny");

    expect(
      await screen.findByText(/Only calls to acme_list_issues/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Only denied calls/)).toBeInTheDocument();
  });

  it("tells an empty narrowing apart from an empty log", async () => {
    // A reader arrives here by clicking a bar. An empty result that read "no requests
    // yet" would contradict the bar they just clicked, and one of the two would be
    // believed.
    show([], "/admin/door-calls?tool=nonesuch");

    expect(await screen.findByText("No matching requests")).toBeInTheDocument();
    expect(screen.queryByText("No requests yet")).not.toBeInTheDocument();
  });

  it("still says the log is empty when it is, and no filter is on", async () => {
    show([]);

    expect(await screen.findByText("No requests yet")).toBeInTheDocument();
    expect(screen.queryByText("No matching requests")).not.toBeInTheDocument();
  });

  it("drops one narrowing without touching the others", async () => {
    show([record()], "/admin/door-calls?tool=acme_list_issues&decision=deny");
    const drop = await screen.findByRole("button", {
      name: /Only calls to acme_list_issues/,
    });

    fireEvent.click(drop);

    // Awaited rather than asserted synchronously: dropping a filter changes the URL,
    // which refetches, and the assertion has to be on the settled page — otherwise the
    // refetch resolves after the test and React says so.
    await waitFor(() =>
      expect(
        screen.queryByText(/Only calls to acme_list_issues/),
      ).not.toBeInTheDocument(),
    );
    expect(screen.getByText(/Only denied calls/)).toBeInTheDocument();
  });

  it("writes the typed filters into the URL, and keeps the ones it does not offer", async () => {
    // The bar covers the six a person types. A link from the Overview narrowed to
    // denials stays narrowed to denials while the reader adds a tool — the other five
    // keys are left as they arrived.
    show([record()], "/admin/door-calls?decision=deny");
    await screen.findByText("acme_list_issues");

    await userEvent.type(screen.getByLabelText("Tool"), "acme_list_issues");
    await userEvent.type(screen.getByLabelText("Token"), "tok_9311cad7");
    await userEvent.selectOptions(screen.getByLabelText("Outcome"), "not recorded");
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));

    expect(await screen.findByText(/Only calls to acme_list_issues/)).toBeInTheDocument();
    expect(screen.getByText(/Only calls from tok_9311cad7/)).toBeInTheDocument();
    expect(screen.getByText(/Only denied calls/)).toBeInTheDocument();
    expect(api.adminDoorCalls).toHaveBeenLastCalledWith(
      expect.objectContaining({
        tool: "acme_list_issues",
        principalId: "tok_9311cad7",
        decision: "deny",
        outcome: "",
      }),
    );
  });

  it("starts the bar from the URL, so a link's filters can be edited rather than retyped", async () => {
    show([record()], "/admin/door-calls?tool=acme_list_issues&since=2026-08-01");
    await screen.findByText("acme_list_issues", { selector: "button" });

    expect(screen.getByLabelText("Tool")).toHaveValue("acme_list_issues");
    expect(screen.getByLabelText("From")).toHaveValue("2026-08-01");
  });

  it("shows no filter bar at all on an unfiltered page", async () => {
    show([record()]);
    await screen.findByText("acme_list_issues");

    expect(screen.queryByText("Showing:")).not.toBeInTheDocument();
  });
});
