/** The Administration page, and the two things it must not get wrong.
 *
 * It renders a log, so most of it is a table — and a table is not what is worth asserting.
 * What is:
 *
 *   - **the 403 is rendered as the server's own sentence**, because a person who deep-
 *     links here without the role must be told something they can act on rather than
 *     shown a blank page or bounced to a sign-in that cannot help
 *   - **`detail` is printed rather than parsed**, so an action nobody wrote a branch for
 *     still renders. A screen that switched on `action` would show nothing at all for the
 *     next entry somebody adds to `ADMIN_ACTIONS`
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return { ...actual, api: { adminAudit: vi.fn() } };
});

import AdminPage, { describe as describeDetail } from "./AdminPage";
import { api, ApiError } from "../../lib/api";
import type { AdminRecord } from "../../lib/types";

// Each fixture row gets its own sequence number, as the store gives one: the key a
// row is rendered by and the cursor a page turns (110f).
let seq = 0;

function record(overrides: Partial<AdminRecord> = {}): AdminRecord {
  return {
    id: ++seq,
    v: 1,
    ts: "2026-08-09T10:15:00+00:00",
    actor_kind: "user",
    actor_id: "u_9311cad7",
    action: "grant.create",
    target_kind: "agent",
    target_id: "triage-bot",
    detail: { role: "editor", grantee: "user:u_sam" },
    ...overrides,
  };
}

function show(rows: AdminRecord[]) {
  vi.mocked(api.adminAudit).mockResolvedValue(rows);
  return render(
    <MemoryRouter>
      <AdminPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(api.adminAudit).mockReset();
});

describe("the log", () => {
  it("renders who changed what, and to what", async () => {
    show([record()]);

    expect(await screen.findByText("grant.create")).toBeInTheDocument();
    expect(screen.getByText("user:u_9311cad7")).toBeInTheDocument();
    // The target cell is the kind and, since 110f, the id as a link — two elements.
    expect(screen.getByRole("link", { name: "triage-bot" }).closest("td")).toHaveTextContent(
      "agent:triage-bot",
    );
  });

  it("links the target to its page where one exists, and the actor stays text", async () => {
    // 110f, plan 107 D10: the agent a grant was about is one click away rather than a
    // name to copy into the address bar. The actor is a person, and people have no page
    // a link could go to from here.
    show([record()]);

    expect(await screen.findByRole("link", { name: "triage-bot" })).toHaveAttribute(
      "href",
      "/agents/triage-bot",
    );
    expect(screen.queryByRole("link", { name: /u_9311cad7/ })).toBeNull();
  });

  it("counts what is on screen and offers older rows when there are older rows", async () => {
    // A hundred rows is a page, not a window: the count is the count, and *Show older*
    // is the way to the rest. The old title — "the 200 most recent" — described a cap
    // that no longer exists. A hundred and one answers mean a hundred shown: the extra
    // row is the hook asking *is there more*, and it is not rendered.
    show(Array.from({ length: 101 }, () => record()));

    expect(await screen.findByText("100 changes")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Show older" })).toBeInTheDocument();
    expect(screen.queryByText(/older records are not shown/)).toBeNull();
  });

  it("offers nothing older when the log ends exactly on a page boundary", async () => {
    // What the old short-page guess got wrong on every log whose length is a multiple
    // of the page: a click that comes back with nothing.
    show(Array.from({ length: 100 }, () => record()));

    expect(await screen.findByText("100 changes")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Show older" })).toBeNull();
  });

  it("asks for the rows before the oldest one shown, and appends them", async () => {
    // The cursor is an id, never an offset — a row appended between the two requests
    // would shift an offset by one and repeat or skip a row; an id does not move.
    const first = Array.from({ length: 101 }, (_, i) => record({ id: 500 - i }));
    vi.mocked(api.adminAudit).mockResolvedValueOnce(first).mockResolvedValueOnce([
      record({ id: 400, action: "role.grant" }),
    ]);
    render(
      <MemoryRouter>
        <AdminPage />
      </MemoryRouter>,
    );

    await userEvent.click(await screen.findByRole("button", { name: "Show older" }));

    expect(await screen.findByText("101 changes")).toBeInTheDocument();
    expect(api.adminAudit).toHaveBeenLastCalledWith({ before: 401, limit: 101 });
    expect(screen.getByText("role.grant")).toBeInTheDocument();
    // A short page is the end of the log, so the button goes.
    expect(screen.queryByRole("button", { name: "Show older" })).toBeNull();
  });

  it("offers nothing older after a short first page", async () => {
    show([record(), record()]);

    expect(await screen.findByText("2 changes")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Show older" })).toBeNull();
  });

  it("prints detail rather than switching on the action", async () => {
    show([record({ action: "role.grant", target_kind: "user", target_id: "u_sam", detail: { role: "admin" } })]);

    expect(await screen.findByText("role.grant")).toBeInTheDocument();
    expect(screen.getByText("role=admin")).toBeInTheDocument();
  });

  it("renders an action nobody here has heard of", async () => {
    // The property that matters: `ADMIN_ACTIONS` grows every time a method comes into
    // scope, and this screen must not be a second place that has to be edited when it
    // does. A `switch (action)` would render nothing here.
    show([record({ action: "something.new", detail: { whatever: "yes" } })]);

    expect(await screen.findByText("something.new")).toBeInTheDocument();
    expect(screen.getByText("whatever=yes")).toBeInTheDocument();
  });

  it("says so when nothing has been changed yet", async () => {
    show([]);

    expect(await screen.findByText("No changes yet")).toBeInTheDocument();
  });

  it("asks for the log once and does not poll it", async () => {
    show([record()]);
    await screen.findByText("grant.create");

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(api.adminAudit).toHaveBeenCalledTimes(1);
  });
});

describe("somebody who is not an administrator", () => {
  it("is shown the server's own sentence rather than a blank page", async () => {
    vi.mocked(api.adminAudit).mockRejectedValue(
      new ApiError(
        403,
        "this needs an administrator of this workspace, and you are not one. Whoever runs your workspace can grant it.",
      ),
    );

    render(
      <MemoryRouter>
        <AdminPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText(/you are not one/)).toBeInTheDocument();
    // `Failure`'s 403 branch, and the sentence that stops somebody trying to fix it by
    // signing in again — which is a loop, because a 403 means authenticating again will
    // not help.
    expect(screen.getByText(/Signing in again will not change this/)).toBeInTheDocument();
  });

  it("does not render the table at all", async () => {
    vi.mocked(api.adminAudit).mockRejectedValue(new ApiError(403, "not an administrator"));

    render(
      <MemoryRouter>
        <AdminPage />
      </MemoryRouter>,
    );

    await screen.findByText(/not an administrator/);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });
});

describe("detail, as one line", () => {
  it("sorts its keys so two records of one action read the same shape", () => {
    expect(describeDetail(record({ detail: { role: "editor", grantee: "sam" } }))).toBe(
      "grantee=sam, role=editor",
    );
  });

  it("drops what was never set rather than rendering empty brackets", () => {
    expect(
      describeDetail(record({ detail: { role: "user", tools: [], scope: {}, note: "" } })),
    ).toBe("role=user");
  });

  it("flattens a list the way --admin-log does", () => {
    expect(describeDetail(record({ detail: { fields: ["name", "system"] } }))).toBe(
      "fields=name system",
    );
  });
});
