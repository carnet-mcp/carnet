/** Connector onboarding, and the things a screen over this API must not get wrong.
 *
 *   - **the ordering is enforced with a sentence, not by hiding things.** A connector's
 *     URL has to be on an approved host, so registration is genuinely unavailable until
 *     one exists — and a page that simply omitted the form would look complete while the
 *     thing somebody came to do was invisible.
 *   - **approving a host that can never be dialled says so.** The row is real and the
 *     control is not in force; being told plain *yes* about that is the exact failure the
 *     egress module is written against, and this is the only place a person sees it.
 *   - **revoking a host does not delete the connectors on it, and the screen says which.**
 *     The opposite reading is the one somebody assumes, and assuming it means believing an
 *     integration was destroyed when the row is waiting for the host to come back.
 *
 * Step 091 rewrote the copy and the layout without touching a single request, and added
 * two claims of its own:
 *
 *   - **the badge and the sentence never disagree.** `status()` and `describe()` are two
 *     functions read at two speeds by two people, computed from the same three conditions
 *     in the same order. A card whose badge says *Ready* under a sentence saying nothing
 *     is switched on is worse than either alone.
 *   - **the address a preset needs can be allowed where it is named** — the same request
 *     the allowlist form posts, offered where the question is asked, and offered to nobody
 *     the server would refuse.
 */

import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return {
    ...actual,
    api: {
      listHosts: vi.fn(),
      listConnectors: vi.fn(),
      approveHost: vi.fn(),
      revokeHost: vi.fn(),
      registerConnector: vi.fn(),
      listRecipes: vi.fn(),
    },
  };
});

import ConnectorsPage, { describe as describeConnector, asserted } from "./ConnectorsPage";
import { api, ApiError } from "../../lib/api";
import type { ConnectorSummary, HostEntry } from "../../lib/types";

function host(overrides: Partial<HostEntry> = {}): HostEntry {
  return {
    host: "mcp.acme.com",
    allowed_by: "user:u_9311",
    allowed_at: "2026-08-09T10:00:00+00:00",
    note: "",
    warning: "",
    ...overrides,
  };
}

function connector(overrides: Partial<ConnectorSummary> = {}): ConnectorSummary {
  return {
    connector_id: "jira",
    description: "",
    transport: "http",
    url: "https://mcp.acme.com/mcp",
    credential_env: "",
    credential_ref: "",
    vetted: 0,
    writes: 0,
    host: "mcp.acme.com",
    host_allowed: true,
    oauth: null,
    allow_asserted_identity: false,
    from_recipe: "",
    ...overrides,
  };
}

/** A recipe with a consent flow and a proposed tool — the shape with the most to get
 *  wrong. `verified_on: null` is the default because it is what every recipe ships as
 *  until somebody completes a consent flow against the vendor. */
function show(hosts: HostEntry[] = [], connectors: ConnectorSummary[] = []) {
  vi.mocked(api.listHosts).mockResolvedValue(hosts);
  vi.mocked(api.listConnectors).mockResolvedValue(connectors);
  return render(
    <MemoryRouter>
      <ConnectorsPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(api.listHosts).mockReset();
  vi.mocked(api.listConnectors).mockReset();
  vi.mocked(api.approveHost).mockReset();
  vi.mocked(api.revokeHost).mockReset();
  vi.mocked(api.registerConnector).mockReset();
  vi.mocked(api.listRecipes).mockReset();
  vi.mocked(api.listRecipes).mockResolvedValue([]);
});

describe("somebody who may not administer this workspace", () => {
  it("gets the server's sentence and no form under it", async () => {
    // **A defect found by pointing a browser at this page as the second person.** The
    // route is deep-linkable on purpose — a 404 would tell an authenticated colleague this
    // product has no administration — so a non-administrator does land here, sees the 403,
    // and until this condition existed also saw a complete, working-looking host-approval
    // form beneath it. That is `your_role`'s lesson exactly: a control that refuses the
    // person who pressed it reads as a bug where a sentence reads as a rule.
    const refusal = new ApiError(
      403,
      "this needs an administrator of this workspace, and you are not one.",
    );
    vi.mocked(api.listHosts).mockRejectedValue(refusal);
    vi.mocked(api.listConnectors).mockRejectedValue(refusal);
    render(
      <MemoryRouter>
        <ConnectorsPage />
      </MemoryRouter>,
    );

    expect(await screen.findAllByText(/you are not one/)).not.toHaveLength(0);
    expect(screen.queryByPlaceholderText("mcp.acme.com")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Add a connector" })).not.toBeInTheDocument();
  });

  it("is not told the allowlist is empty when it merely could not be read", async () => {
    // Two different facts, and only one of them is true. "Approve a host first" points at
    // a form that is not there and would not work if it were.
    vi.mocked(api.listHosts).mockRejectedValue(new ApiError(403, "not an administrator"));
    vi.mocked(api.listConnectors).mockResolvedValue([]);
    render(
      <MemoryRouter>
        <ConnectorsPage />
      </MemoryRouter>,
    );

    await screen.findAllByText(/not an administrator/);
    expect(screen.queryByText(/Approve a host first/)).not.toBeInTheDocument();
  });
});

describe("adding one", () => {
  it("is a link to the setup, offered once the list has loaded (107 D4)", async () => {
    // The six-step setup is its own pages; this page is the list and the allowlist.
    // Offered whether or not a host is approved, because approving one is the setup's
    // second step, where the question is asked.
    show([], []);

    expect(await screen.findByRole("link", { name: "Add a connector" })).toHaveAttribute(
      "href",
      "/admin/connectors/new",
    );
    expect(screen.queryByRole("button", { name: "Register" })).not.toBeInTheDocument();
    expect(screen.queryByPlaceholderText("jira")).not.toBeInTheDocument();
  });
});

describe("hosts", () => {
  it("renders the warning after approving one that will never be dialled", async () => {
    vi.mocked(api.approveHost).mockResolvedValue({
      host: "localhost",
      note: "",
      warning:
        "Recorded, but 'localhost' will NOT be dialled: it is a name for this machine.",
    });
    show([host()]);

    await userEvent.type(await screen.findByPlaceholderText("mcp.acme.com"), "localhost");
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    expect(await screen.findByText(/will NOT be dialled/)).toBeInTheDocument();
  });

  it("renders a pasted URL as the server's sentence about what to strip", async () => {
    vi.mocked(api.approveHost).mockRejectedValue(
      new ApiError(
        400,
        "'https://mcp.acme.com/mcp' contains a scheme. The allowlist is keyed on the " +
          "host alone. Pass just the hostname — for a URL, take its host first.",
      ),
    );
    show([host()]);

    await userEvent.type(
      await screen.findByPlaceholderText("mcp.acme.com"),
      "https://mcp.acme.com/mcp",
    );
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    // The whole reason the host goes in the request body rather than a path segment: a
    // `/` in a path is a bare 404 with nothing to say, and this sentence is what a person
    // acts on.
    expect(await screen.findByText(/Pass just the hostname/)).toBeInTheDocument();
  });

  it("revoking is a two-step, and the first click revokes nothing", async () => {
    // 061: this was the app's one destructive control that acted on first click —
    // and the one that can strand every connector on the host. The confirm says the
    // stranding BEFORE the click that causes it, which the post-hoc notice below
    // could only report after.
    vi.mocked(api.revokeHost).mockResolvedValue({
      host: "mcp.acme.com",
      removed: true,
      stranded: [],
    });
    show([host()], [connector()]);

    await userEvent.click(await screen.findByRole("button", { name: "Revoke" }));

    expect(api.revokeHost).not.toHaveBeenCalled();
    expect(
      screen.getByText(/Every connector on this host stops connecting/),
    ).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(api.revokeHost).not.toHaveBeenCalled();
    expect(screen.queryByText(/Revoke mcp.acme.com\?/)).not.toBeInTheDocument();
  });

  it("names the connectors a revoke stranded, and says they were not deleted", async () => {
    vi.mocked(api.revokeHost).mockResolvedValue({
      host: "mcp.acme.com",
      removed: true,
      stranded: ["jira", "linear"],
    });
    show([host()], [connector()]);

    await userEvent.click(await screen.findByRole("button", { name: "Revoke" }));
    // The confirm is the one alert on the page, and its Revoke is the one that acts.
    await userEvent.click(
      within(screen.getByRole("alert")).getByRole("button", { name: "Revoke" }),
    );

    expect(await screen.findByText(/jira, linear/)).toBeInTheDocument();
    expect(
      screen.getByText(/Their registrations and approved tools are kept/),
    ).toBeInTheDocument();
  });

  it("marks an unreachable row in the list, not only at the moment of approval", async () => {
    // Whoever reads the allowlist next was not the person who approved it, and this row
    // is indistinguishable from a working one otherwise.
    show([host({ host: "127.0.0.1", warning: "it is a loopback address" })]);

    expect(await screen.findByText("not reachable")).toBeInTheDocument();
  });
});

describe("the sentence per connector", () => {
  it("says a revoked host keeps everything, and leads with that", () => {
    const said = describeConnector(connector({ host_allowed: false, vetted: 3 }));

    expect(said).toMatch(/^mcp\.acme\.com is not an approved host/);
    expect(said).toContain("Its approved tools are kept");
  });

  it("says nothing is reachable when nothing is vetted", () => {
    expect(describeConnector(connector({ vetted: 0 }))).toContain(
      "No tools approved yet",
    );
  });

  it("distinguishes vetted-without-a-consent-flow from vetted-with-one", () => {
    const without = describeConnector(connector({ vetted: 2 }));
    const with_ = describeConnector(
      connector({
        vetted: 2,
        oauth: {
          connector_id: "jira",
          authorize_endpoint: "a",
          token_endpoint: "t",
          revoke_endpoint: "",
          client_id: "c",
          scopes: [],
          scope_notes: {},
          authorize_params: {},
          configured_by: "",
          configured_at: "",
        },
      }),
    );

    // The distinction is *whose account a run acts as*, which is the whole of 7a and 7b
    // and is invisible from a tool count.
    expect(without).toContain("cannot connect their own accounts");
    expect(without).toContain("Calls use the shared credential");
    expect(with_).toContain("Users can connect their own accounts");
    expect(without).not.toEqual(with_);
  });

  it("gets the singular right", () => {
    expect(describeConnector(connector({ vetted: 1 }))).toContain("1 tool approved");
    expect(describeConnector(connector({ vetted: 2 }))).toContain("2 tools approved");
  });
});

describe("which connectors believe a caller's claim", () => {
  // **Scoped to the row, never to the page.** The registration form above these rows
  // describes the same control in the same words — deliberately, because two screens
  // wording one control differently is how somebody ends up believing the wrong thing — so
  // a page-wide assertion here would pass on the form's copy and prove nothing about the
  // listing. 035f's e2e paid for this lesson twice; it applies to a rendered DOM identically.
  const row = (id: string) => screen.getByText(id).closest(".conn-card") as HTMLElement;

  it("marks the one that does, in the list, with the sentence under it", async () => {
    // The question the schema comment says this screen exists to answer at a glance:
    // *"which of our connectors accept asserted identity"*.
    show([host()], [connector({ allow_asserted_identity: true })]);

    await screen.findByText("jira");
    expect(row("jira")).toHaveTextContent("asserted identity");
    expect(row("jira")).toHaveTextContent(/without verification/);
  });

  it("says nothing at all on the resting posture", async () => {
    // **The exception is marked; the norm is not.** This page's other two tags mark
    // exceptions too, and a row on every connector saying *verified only* would bury the
    // one row a security review came to find.
    show([host()], [connector()]);

    await screen.findByText("jira");
    expect(row("jira")).not.toHaveTextContent("asserted identity");
    expect(row("jira")).not.toHaveTextContent(/without verification/);
  });

  it("is a second function beside describe(), and answers a different question", () => {
    // Orthogonal to `describe()`'s three-branch state machine — independently true or false
    // in every one of its branches — and confusable with `VettedTool.identity`, which is
    // whose account a tool acts as rather than whether a claim is believed. One sentence
    // carrying both is how the two merge in somebody's head.
    expect(asserted(connector())).toBe("");
    expect(asserted(connector({ allow_asserted_identity: true }))).toContain("asserted");
    expect(describeConnector(connector({ allow_asserted_identity: true }))).not.toContain(
      "asserted",
    );
  });
});
