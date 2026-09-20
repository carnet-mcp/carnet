/** The people screen, and the two things it must not get wrong.
 *
 *   - **cutting somebody off names what stops and what stays**, and goes through the
 *     one route; the caller's own row is refused in the server's words, rendered
 *     verbatim because the sentence says the way back.
 *   - **a restatement is reported as one.** `changed: false` means the seam wrote no
 *     record, and a screen that says *cut off* about somebody it did not cut off is a
 *     screen an administrator cannot trust.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return {
    ...actual,
    api: { listPeople: vi.fn(), disablePerson: vi.fn(), enablePerson: vi.fn() },
  };
});

import PeoplePage from "./PeoplePage";
import { api, ApiError } from "../../lib/api";
import { MeContext } from "../../lib/me";
import type { PersonEntry } from "../../lib/types";

function person(overrides: Partial<PersonEntry> = {}): PersonEntry {
  return {
    id: "u_sam",
    email: "sam@acme.com",
    display_name: "Sam",
    status: "active",
    issuer: "https://acme.okta.example",
    external_id: "",
    signed_in: true,
    last_seen_at: "2026-09-15T09:00:00+00:00",
    ...overrides,
  };
}

const PRIYA = person({ id: "u_priya", email: "priya@acme.com", display_name: "Priya" });

function show(people: PersonEntry[] = [PRIYA, person()]) {
  vi.mocked(api.listPeople).mockResolvedValue(people);
  return render(
    <MeContext.Provider
      value={{
        me: { principal: "user:u_priya", kind: "user", email: "priya@acme.com", display_name: "Priya", admin: true },
        settled: true,
      }}
    >
      <MemoryRouter>
        <PeoplePage />
      </MemoryRouter>
    </MeContext.Provider>,
  );
}

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn === "function" && "mockReset" in fn) vi.mocked(fn).mockReset();
  }
});

describe("the list", () => {
  it("marks you, the cut off, and the ones the directory sent who have not arrived", async () => {
    show([
      PRIYA,
      person({ status: "disabled" }),
      person({ id: "u_tom", email: "tom@acme.com", signed_in: false, last_seen_at: "", external_id: "dir-8f2c" }),
    ]);

    const priya = (await screen.findByText("priya@acme.com")).closest(".row")!;
    expect(priya).toHaveTextContent("you");
    const sam = screen.getByText("sam@acme.com").closest(".row")!;
    expect(sam).toHaveTextContent("cut off");
    expect(sam.querySelector("button")).toHaveTextContent("Let back in");
    const tom = screen.getByText("tom@acme.com").closest(".row")!;
    expect(tom).toHaveTextContent("never signed in");
    expect(tom).toHaveTextContent("Sent by your directory; has not signed in yet.");
  });
});

describe("cutting somebody off", () => {
  it("names what stops and what stays, then calls the route", async () => {
    vi.mocked(api.disablePerson).mockResolvedValue({ id: "u_sam", email: "sam@acme.com", status: "disabled", changed: true });
    show();

    const sam = (await screen.findByText("sam@acme.com")).closest(".row")!;
    await userEvent.click(sam.querySelector("button")!);

    expect(await screen.findByText(/Their sign-in stops now/)).toBeInTheDocument();
    expect(screen.getByText(/nothing is deleted/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Cut off" }));

    await waitFor(() => expect(api.disablePerson).toHaveBeenCalledWith("u_sam"));
    expect(api.listPeople).toHaveBeenCalledTimes(2);
  });

  it("renders the refusal for your own row verbatim, and closes the confirmation", async () => {
    vi.mocked(api.disablePerson).mockRejectedValue(
      new ApiError(400, "you cannot disable yourself: your sign-in would be refused from now and there is no way back from a browser. Another administrator can, or the shell can (carnet --disable-user)."),
    );
    show();

    const priya = (await screen.findByText("priya@acme.com")).closest(".row")!;
    await userEvent.click(priya.querySelector("button")!);
    await userEvent.click(screen.getByRole("button", { name: "Cut off" }));

    expect(await screen.findByText(/no way back from a browser/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Cut off" })).not.toBeInTheDocument();
  });

  it("says when nothing changed rather than claiming the act", async () => {
    vi.mocked(api.enablePerson).mockResolvedValue({ id: "u_sam", email: "sam@acme.com", status: "active", changed: false });
    show([PRIYA, person({ status: "disabled" })]);

    const sam = (await screen.findByText("sam@acme.com")).closest(".row")!;
    await userEvent.click(sam.querySelector("button")!);

    await waitFor(() => expect(api.enablePerson).toHaveBeenCalledWith("u_sam"));
    expect(await screen.findByText("sam@acme.com was already active.")).toBeInTheDocument();
  });
});
