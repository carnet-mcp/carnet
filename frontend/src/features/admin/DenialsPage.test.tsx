/** The access-denial log, and the things it must not get wrong.
 *
 * Most of it is a table and a table is not worth asserting. What is:
 *
 *   - **`held: ""` is a word, not an empty cell.** It is the server's answer — this
 *     principal held nothing at all — and it is the whole difference between a stranger
 *     probing and a `user` reaching for `editor`. A blank cell reads as a field that
 *     failed to arrive
 *   - **filtering reaches the server.** The list is the most recent 200 records, so a
 *     client narrowing that page would answer *"which of these came from the door"* with
 *     *"which of the last two hundred"* — the same lie as silent truncation
 *   - **a kind this file has never heard of still renders**, because the column is a
 *     value and never a switch. That is what let `tool` arrive without a frontend change
 *     and it is the property that has to survive the next one
 *   - **the 403 is the server's own sentence**, because somebody who deep-links here
 *     without the role must be told something they can act on
 */

import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return { ...actual, api: { adminDenials: vi.fn() } };
});

import DenialsPage from "./DenialsPage";
import { api, ApiError } from "../../lib/api";
import type { DenialRecord } from "../../lib/types";

function record(overrides: Partial<DenialRecord> = {}): DenialRecord {
  return {
    v: 1,
    ts: "2026-08-09T10:15:00+00:00",
    principal_kind: "user",
    principal_id: "u_sam",
    resource_kind: "agent",
    resource_id: "payroll-bot",
    required: "user",
    held: "",
    ...overrides,
  };
}

function show(rows: DenialRecord[]) {
  vi.mocked(api.adminDenials).mockResolvedValue(rows);
  return render(
    <MemoryRouter>
      <DenialsPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(api.adminDenials).mockReset();
});

describe("the log", () => {
  it("renders who was refused, and what they asked for", async () => {
    show([record()]);

    expect(await screen.findByText("payroll-bot")).toBeInTheDocument();
    expect(screen.getByText("u_sam")).toBeInTheDocument();
    expect(screen.getByText("user")).toBeInTheDocument();
  });

  it("says so when nothing has been denied yet", async () => {
    show([]);

    expect(await screen.findByText("No denied requests")).toBeInTheDocument();
    // An empty log is a true answer rather than a missing one, and the page says what
    // would fill it.
    expect(screen.getByText(/Denied requests appear here/)).toBeInTheDocument();
  });

  it("asks for the log once and does not poll it", async () => {
    show([record()]);
    await screen.findByText("payroll-bot");

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(api.adminDenials).toHaveBeenCalledTimes(1);
  });
});

describe("required and held", () => {
  it("renders holding nothing as a word rather than an empty cell", async () => {
    show([record({ required: "user", held: "" })]);

    expect(await screen.findByText("nothing")).toBeInTheDocument();
  });

  it("keeps a stranger and a person reaching too high visibly apart", async () => {
    // The pair is one fact in two columns: `user` probing for `editor` is a different
    // event from somebody with no access at all, and the log exists to say which.
    show([
      record({ principal_id: "u_sam", required: "editor", held: "user" }),
      record({ principal_id: "u_pat", required: "user", held: "" }),
    ]);

    const rows = await screen.findAllByRole("row");
    expect(within(rows[1]).getByText("user")).toBeInTheDocument();
    expect(within(rows[2]).getByText("nothing")).toBeInTheDocument();
  });
});

describe("what the refusal was about", () => {
  it("renders a kind this file has never heard of", async () => {
    // The property that let `tool` arrive with migration 040 and no frontend change,
    // and the one that has to survive the next kind. The column is a value, not a
    // switch — a page that branched on the three it knows would render nothing at all
    // for the fourth.
    show([record({ resource_kind: "quantum-widget", resource_id: "w-1" })]);

    expect(await screen.findByText(/quantum-widget/)).toBeInTheDocument();
    expect(screen.getByText("w-1")).toBeInTheDocument();
  });

  it("renders a refusal that names no finer thing than its surface", async () => {
    // `require_admin`'s callers often pass no `what`, so `resource_id` is `""`. The kind
    // is still the answer, and a trailing separator with nothing after it would read as
    // a value that went missing.
    show([record({ resource_kind: "admin", resource_id: "", required: "admin" })]);

    const rows = await screen.findAllByRole("row");
    const cells = within(rows[1]).getAllByRole("cell");
    // The kind alone, with no trailing separator: `admin:` with nothing after it would
    // read as a value that went missing on the way here.
    expect(cells[2]).toHaveTextContent(/^admin$/);
  });

  it("asks the server for one kind rather than filtering what it was given", async () => {
    // The assertion the backend half of this chunk exists for. A client narrowing the
    // most recent 200 records would answer "which of these came from the door" with
    // "which of the last two hundred", which is a lie about completeness in a log view.
    show([record()]);
    await screen.findByText("payroll-bot");

    await userEvent.click(screen.getByRole("button", { name: "tool" }));

    expect(api.adminDenials).toHaveBeenLastCalledWith(
      expect.objectContaining({ resourceKind: "tool" }),
    );
  });

  it("sends no kind at all when the filter is cleared", async () => {
    // An empty string is a value the server refuses for this parameter, so "no filter"
    // has to be an absent one rather than a blank one.
    show([record()]);
    await screen.findByText("payroll-bot");

    await userEvent.click(screen.getByRole("button", { name: "tool" }));
    await userEvent.click(screen.getByRole("button", { name: "all" }));

    expect(api.adminDenials).toHaveBeenLastCalledWith(
      expect.objectContaining({ resourceKind: undefined }),
    );
  });
});

describe("the two incident questions", () => {
  it("asks what else this person probed, from the row itself", async () => {
    show([record({ principal_id: "u_sam" })]);
    await screen.findByText("payroll-bot");

    await userEvent.click(screen.getByRole("button", { name: "u_sam" }));

    expect(api.adminDenials).toHaveBeenLastCalledWith(
      expect.objectContaining({ principalId: "u_sam" }),
    );
  });

  it("asks who probed this resource, from the row itself", async () => {
    show([record({ resource_id: "payroll-bot" })]);
    await screen.findByText("payroll-bot");

    await userEvent.click(screen.getByRole("button", { name: "payroll-bot" }));

    expect(api.adminDenials).toHaveBeenLastCalledWith(
      expect.objectContaining({ resourceId: "payroll-bot" }),
    );
  });

  it("never renders a superseded filter's rows under the current one", async () => {
    // The bug this page was the first to be able to reach, pinned at the level somebody
    // would actually hit it: two chips clicked a moment apart, the first request slower
    // than the second. Fixed in `useResource` — asserted here too, because the property
    // that matters is about this screen: a log table showing `tool` rows with `admin`
    // selected is not stale data, it is an answer to a question nobody asked.
    let answerTheFirst: (rows: DenialRecord[]) => void = () => {};
    vi.mocked(api.adminDenials)
      .mockResolvedValueOnce([record({ resource_id: "on-load" })])
      .mockImplementationOnce(
        () =>
          new Promise<DenialRecord[]>((resolve) => {
            answerTheFirst = resolve;
          }),
      )
      .mockResolvedValue([
        record({ resource_kind: "admin", resource_id: "the-admin-row" }),
      ]);

    render(
      <MemoryRouter>
        <DenialsPage />
      </MemoryRouter>,
    );
    await screen.findByText("on-load");

    await userEvent.click(screen.getByRole("button", { name: "tool" }));
    await userEvent.click(screen.getByRole("button", { name: "admin" }));
    expect(await screen.findByText("the-admin-row")).toBeInTheDocument();

    // The abandoned request answers, late.
    answerTheFirst([record({ resource_kind: "tool", resource_id: "the-stale-row" })]);
    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(screen.queryByText("the-stale-row")).not.toBeInTheDocument();
    expect(screen.getByText("the-admin-row")).toBeInTheDocument();
  });

  it("lets one filter go without dropping the other", async () => {
    // Found by using the page rather than by reading it: the chips can clear the kind,
    // and before this the only way to drop a principal filter was "Show everything",
    // which also threw away the kind. Narrowing to a person and then widening the kind
    // is the ordinary shape of an incident, and it was a dead end.
    show([record({ principal_id: "u_sam" })]);
    await screen.findByText("payroll-bot");

    await userEvent.click(screen.getByRole("button", { name: "u_sam" }));
    await userEvent.click(screen.getByRole("button", { name: "tool" }));

    await userEvent.click(
      screen.getByRole("button", { name: /clear actor filter/i }),
    );

    expect(api.adminDenials).toHaveBeenLastCalledWith(
      expect.objectContaining({ principalId: undefined, resourceKind: "tool" }),
    );
  });

  it("tells an empty filter apart from an empty log", async () => {
    // Two facts that look identical and are not: "nothing was ever refused" needs no
    // action, and "your filter matched nothing" has one.
    vi.mocked(api.adminDenials)
      .mockResolvedValueOnce([record()])
      .mockResolvedValue([]);

    render(
      <MemoryRouter>
        <DenialsPage />
      </MemoryRouter>,
    );
    await screen.findByText("payroll-bot");

    await userEvent.click(screen.getByRole("button", { name: "tool" }));

    expect(await screen.findByText("No matching requests")).toBeInTheDocument();
    expect(screen.queryByText("No denied requests")).not.toBeInTheDocument();
  });
});

describe("somebody who is not an administrator", () => {
  it("is shown the server's own sentence rather than a blank page", async () => {
    vi.mocked(api.adminDenials).mockRejectedValue(
      new ApiError(
        403,
        "this needs an administrator of this workspace, and you are not one. Whoever runs your workspace can grant it.",
      ),
    );

    render(
      <MemoryRouter>
        <DenialsPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText(/you are not one/)).toBeInTheDocument();
    expect(screen.getByText(/Signing in again will not change this/)).toBeInTheDocument();
  });

  it("does not render the table at all", async () => {
    vi.mocked(api.adminDenials).mockRejectedValue(
      new ApiError(403, "not an administrator"),
    );

    render(
      <MemoryRouter>
        <DenialsPage />
      </MemoryRouter>,
    );

    await screen.findByText(/not an administrator/);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });
});
