/** The frame, and the one decision in it that is not decoration.
 *
 * `AppShell` had no tests, which was defensible while it was a nav bar and an email
 * address. It stopped being defensible when it started **deciding what to offer based on
 * who you are** — because that is the `your_role` class of bug, and 10d's note is that
 * the only way it was ever found was by looking.
 *
 * Three properties, and the third is the one somebody would undo:
 *
 *   - a non-administrator is not offered Administration
 *   - an administrator is
 *   - **a failing `/me` fails closed and renders nothing about it** — the shell wraps
 *     every screen, so an error banner here would cover the page somebody asked for with
 *     a complaint about a nav item
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return { ...actual, api: { me: vi.fn() } };
});

// **One frozen object, not a fresh literal per call.** `AppShell` reads the session
// through `useSyncExternalStore`, which compares snapshots by identity — a mock returning
// a new object each time is an infinite render loop, and React says so as
// "Maximum update depth exceeded" rather than as anything about this mock.
const SESSION = {
  state: "in",
  claims: { sub: "priya@acme.com", uid: "u_9311" },
} as const;

vi.mock("../lib/auth", () => ({
  current: () => SESSION,
  subscribe: () => () => {},
  signOut: vi.fn(),
}));

import AppShell from "./AppShell";
import { api, ApiError } from "../lib/api";
import type { Me } from "../lib/types";

function me(overrides: Partial<Me> = {}): Me {
  return {
    principal: "user:u_9311",
    kind: "user",
    email: "priya@acme.com",
    display_name: "Priya",
    admin: false,
    ...overrides,
  };
}

function show() {
  return render(
    <MemoryRouter>
      <AppShell>
        <p>the page</p>
      </AppShell>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(api.me).mockReset();
  localStorage.clear();
});

describe("the Administration nav item", () => {
  it("is not offered to somebody who is not an administrator", async () => {
    vi.mocked(api.me).mockResolvedValue(me({ admin: false }));

    show();

    await screen.findByText("Create MCP");
    await waitFor(() => expect(api.me).toHaveBeenCalled());
    expect(screen.queryByRole("link", { name: "Administration" })).not.toBeInTheDocument();
  });

  it("is offered to an administrator", async () => {
    vi.mocked(api.me).mockResolvedValue(me({ admin: true }));

    show();

    // Asked for by role rather than by text: a sidebar row is an icon *and* a label, so
    // the words are a `<span>` inside the link and the href is on the link around it.
    // The property is "there is a link to the log called Administration", which is what
    // a role query asks and what a text query only asked by accident.
    expect(await screen.findByRole("link", { name: "Administration" })).toHaveAttribute(
      "href",
      "/admin",
    );
  });

  it("brings the rest of the administrative sections with it", async () => {
    // They used to be a second row of navigation drawn inside each administrative page
    // (`AdminNav`). They are in the sidebar now, so this is where "an administrator can
    // reach all of them" is true or not.
    //
    // The list grows with the section, and it has to be updated when it does: 035a added
    // Door traffic and left this test asserting "the other two", so for one step the
    // sidebar had a link nothing here covered. 035b added Access denials and both.
    vi.mocked(api.me).mockResolvedValue(me({ admin: true }));

    show();

    expect(await screen.findByRole("link", { name: "Groups" })).toHaveAttribute(
      "href",
      "/admin/groups",
    );
    expect(screen.getByRole("link", { name: "Connectors" })).toHaveAttribute(
      "href",
      "/admin/connectors",
    );
    expect(screen.getByRole("link", { name: "Door traffic" })).toHaveAttribute(
      "href",
      "/admin/door-calls",
    );
    expect(screen.getByRole("link", { name: "Access denials" })).toHaveAttribute(
      "href",
      "/admin/denials",
    );
  });

  it("takes the whole administrative group away from everybody else", async () => {
    vi.mocked(api.me).mockResolvedValue(me({ admin: false }));

    show();

    await screen.findByText("Create MCP");
    await waitFor(() => expect(api.me).toHaveBeenCalled());
    // Tokens is asserted in the *other* direction just below: it is the first nav item
    // since Connections that a non-administrator must **keep**, and enumerating what a
    // non-admin loses without enumerating what they keep is how a link ends up inside
    // the wrong block with every test still green.
    expect(screen.queryByRole("link", { name: "Groups" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Connectors" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Door traffic" })).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Access denials" }),
    ).not.toBeInTheDocument();
  });

  it("offers Tokens to somebody who is not an administrator", async () => {
    // 035c. `GET /me/tokens` is deliberately roleless — the person who needs it is a
    // non-administrator picking among their own machines — so this link sits outside the
    // administrative group, and that placement is the whole property. Asserted in the
    // `admin: false` case on purpose: an administrator seeing it proves nothing, because
    // an administrator sees everything.
    vi.mocked(api.me).mockResolvedValue(me({ admin: false }));

    show();

    expect(await screen.findByRole("link", { name: "Tokens" })).toHaveAttribute(
      "href",
      "/tokens",
    );
  });

  it("fails closed and silently when /me cannot be read", async () => {
    // The shell is the frame around every other screen. A `/me` that 503s must leave the
    // page underneath readable and must not put a failure banner in the chrome — whoever
    // is genuinely an administrator gets the link on the next load, and the deep link
    // still works because the server decides who may read the log.
    vi.mocked(api.me).mockRejectedValue(new ApiError(503, "storage unavailable"));

    show();

    await waitFor(() => expect(api.me).toHaveBeenCalled());
    expect(screen.queryByText("Administration")).not.toBeInTheDocument();
    expect(screen.queryByText(/storage unavailable/)).not.toBeInTheDocument();
    expect(screen.getByText("the page")).toBeInTheDocument();
  });

  it("asks once rather than polling", async () => {
    vi.mocked(api.me).mockResolvedValue(me({ admin: true }));

    show();
    await screen.findByText("Administration");
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(api.me).toHaveBeenCalledTimes(1);
  });
});

describe("the boundary around the page", () => {
  it("keeps the frame alive when the page throws", async () => {
    // The property 023b's testing pass found missing: with no boundary anywhere, a
    // throwing page unmounted the React root — no nav, no way out but the address bar.
    // The boundary lives here, around `<main>`, so the wreckage is inside the frame
    // and the person is one click from a page that renders.
    vi.mocked(api.me).mockResolvedValue(me());
    vi.spyOn(console, "error").mockImplementation(() => {});
    const Bomb = (): never => {
      throw new Error("this page is broken");
    };

    render(
      <MemoryRouter>
        <AppShell>
          <Bomb />
        </AppShell>
      </MemoryRouter>,
    );

    expect(screen.getByText("this page is broken")).toBeInTheDocument();
    expect(screen.getByText("Create MCP")).toBeInTheDocument();
    expect(screen.getByText("Sign out")).toBeInTheDocument();
  });
});

describe("the collapsed rail", () => {
  it("remembers itself, because it is a preference and not a mode", async () => {
    // A person who collapses the sidebar has said something about how they want to work,
    // and saying it again on every page load would make the control feel broken.
    vi.mocked(api.me).mockResolvedValue(me());
    localStorage.removeItem("ui.sidebar");

    show();

    const toggle = await screen.findByRole("button", { name: "Collapse sidebar" });
    expect(toggle).toHaveAttribute("aria-expanded", "true");

    await userEvent.click(toggle);

    expect(localStorage.getItem("ui.sidebar")).toBe("collapsed");
    expect(
      screen.getByRole("button", { name: "Expand sidebar" }),
    ).toHaveAttribute("aria-expanded", "false");
  });

  it("starts collapsed when that is what was last chosen", async () => {
    vi.mocked(api.me).mockResolvedValue(me());
    localStorage.setItem("ui.sidebar", "collapsed");

    show();

    expect(await screen.findByRole("button", { name: "Expand sidebar" })).toBeInTheDocument();
  });

  it("keeps every destination reachable while it is collapsed", async () => {
    // The labels are hidden with CSS rather than removed, so a collapsed sidebar is a
    // visual state and not a different navigation: the rows keep their names, and a
    // screen reader is told the same thing either way.
    vi.mocked(api.me).mockResolvedValue(me({ admin: true }));
    localStorage.setItem("ui.sidebar", "collapsed");

    show();

    expect(await screen.findByRole("link", { name: "Create MCP" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Administration" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Sign out/ })).toBeInTheDocument();
  });
});

describe("who you are", () => {
  it("is always on screen, because two states are indistinguishable from a bug without it", async () => {
    // An empty agent list and an agent reachable only through a group both look like
    // failures unless the reader is certain which account they are looking at. 9a's
    // verification silently tested the wrong person for a whole pass.
    vi.mocked(api.me).mockResolvedValue(me());

    show();

    expect(await screen.findByText("priya@acme.com")).toBeInTheDocument();
  });
});
