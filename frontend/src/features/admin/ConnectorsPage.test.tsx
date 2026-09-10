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

import { render, screen, waitFor, within } from "@testing-library/react";
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

import ConnectorsPage, {
  describe as describeConnector,
  asserted,
  status,
} from "./ConnectorsPage";
import { api, ApiError } from "../../lib/api";
import type { ConnectorSummary, HostEntry, Recipe } from "../../lib/types";

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
    ...overrides,
  };
}

/** A recipe with a consent flow and a proposed tool — the shape with the most to get
 *  wrong. `verified_on: null` is the default because it is what every recipe ships as
 *  until somebody completes a consent flow against the vendor. */
function recipe(overrides: Partial<Recipe> = {}): Recipe {
  return {
    id: "atlassian-jira",
    name: "Jira",
    description: "Atlassian's hosted MCP server.",
    verified_on: null,
    verified_by: "",
    verified_against: "",
    staleness: "unverified",
    hosts: [
      { host: "mcp.acme.com", why: "The MCP server itself." },
      { host: "auth.atlassian.com", why: "The OAuth token endpoint." },
    ],
    connector: {
      connector_id: "jira",
      url: "https://mcp.acme.com/mcp",
      kind: "http",
      credential_env: "JIRA_TOKEN",
      credential_header: null,
      credential_prefix: null,
      headers: {},
      description: "Jira, over Atlassian's hosted MCP server",
    },
    oauth: {
      authorize_endpoint: "https://auth.atlassian.com/authorize",
      token_endpoint: "https://auth.atlassian.com/oauth/token",
      revoke_endpoint: "",
      scopes: ["read:jira-work"],
      authorize_params: {},
      scope_notes: {},
    },
    tools: [],
    ...overrides,
  };
}

function show(
  hosts: HostEntry[] = [],
  connectors: ConnectorSummary[] = [],
  recipes: Recipe[] = [],
) {
  vi.mocked(api.listHosts).mockResolvedValue(hosts);
  vi.mocked(api.listConnectors).mockResolvedValue(connectors);
  vi.mocked(api.listRecipes).mockResolvedValue(recipes);
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

describe("the ordering", () => {
  it("refuses to offer registration before a host is approved, and says why", async () => {
    show([], []);

    expect(await screen.findByText(/Approve a host first/)).toBeInTheDocument();
    // And the hosts card says the same thing about itself, in its own words.
    expect(
      screen.getByText(/No approved hosts\. Connectors can only connect to approved hosts/),
    ).toBeInTheDocument();
    // Not hidden. A page that dropped the form would look finished while the next thing
    // to do was nowhere.
    expect(screen.queryByRole("button", { name: "Register" })).not.toBeInTheDocument();
  });

  it("offers registration once one is", async () => {
    show([host()], []);

    expect(await screen.findByRole("button", { name: "Register" })).toBeInTheDocument();
  });

  it("does not count a host that can never be dialled as an approved one", async () => {
    // The row exists and the control is not in force, so it must not unlock the stage
    // that depends on it — otherwise somebody registers against `localhost` and the
    // refusal arrives at the first run instead of here.
    show([host({ host: "localhost", warning: "Recorded, but 'localhost' will NOT be dialled" })]);

    expect(await screen.findByText(/Approve a host first/)).toBeInTheDocument();
  });
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
    expect(screen.queryByRole("button", { name: "Register" })).not.toBeInTheDocument();
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

describe("registering", () => {
  it("sends what the form collected and reloads the list", async () => {
    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    show([host()]);

    await userEvent.type(await screen.findByPlaceholderText("jira"), "jira");
    await userEvent.type(
      screen.getByPlaceholderText("https://mcp.acme.com/mcp"),
      "https://mcp.acme.com/mcp",
    );
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() =>
      expect(api.registerConnector).toHaveBeenCalledWith({
        connector_id: "jira",
        url: "https://mcp.acme.com/mcp",
        // 047. Explicit for `allow_asserted_identity`'s reason, and load-bearing in a
        // way that one is not: it decides whether this connector's tools are ever
        // discovered or must be authored, and there is no update path.
        kind: "http",
        credential_env: "",
        // 070. **Both are always sent, and exactly one can be non-empty.** The form
        // offers a choice rather than two boxes, because the server refuses both being
        // set — and sending the unchosen one empty rather than omitting it is what stops
        // a switched choice from leaving the previous answer behind.
        credential_ref: "",
        description: "",
        // 035g. Sent explicitly rather than left to the server's default, because the form
        // has an answer and a request that omits it is a request whose meaning depends on a
        // default somebody has to go and read.
        allow_asserted_identity: false,
      }),
    );
  });

  it("sends a REST connector's own credential scheme, and only for REST", async () => {
    // Step 047. `credential_header`, `credential_prefix` and `headers` have been on the
    // wire since 045a with no way to reach them, so a model vendor reading `x-api-key`
    // was registrable only from a shell. They are REST-only because an MCP server's
    // scheme is protocol convention and a field to change it is a field to break it.
    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    show([host()]);

    await userEvent.click(await screen.findByLabelText(/REST API/));
    await userEvent.type(screen.getByPlaceholderText("jira"), "anthropic");
    await userEvent.type(
      screen.getByPlaceholderText("https://api.acme.com/v1"),
      "https://api.anthropic.com/v1",
    );
    await userEvent.type(screen.getByPlaceholderText("x-api-key"), "x-api-key");
    await userEvent.click(screen.getByRole("button", { name: "Add a header" }));
    await userEvent.type(
      screen.getByPlaceholderText("anthropic-version"),
      "anthropic-version",
    );
    await userEvent.type(screen.getByPlaceholderText("2023-06-01"), "2023-06-01");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() =>
      expect(api.registerConnector).toHaveBeenCalledWith(
        expect.objectContaining({
          connector_id: "anthropic",
          kind: "rest",
          credential_header: "x-api-key",
          headers: { "anthropic-version": "2023-06-01" },
        }),
      ),
    );
  });

  it("shows the real default prefix and sends exactly what is shown", async () => {
    // 061 inverted this test's old contract. The field used to start at "" and be
    // omitted when empty — and the hint's documented way to select the bare token
    // (type a space, delete it) landed back on "", so every x-api-key connector
    // 401ed with a remedy that did not remedy. Now the field starts at the actual
    // default and is always sent: what it shows is what goes in the header.
    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    show([host()]);

    await userEvent.click(await screen.findByLabelText(/REST API/));
    expect(screen.getByLabelText(/Credential prefix/)).toHaveValue("Bearer ");
    await userEvent.type(screen.getByPlaceholderText("jira"), "openmeteo");
    await userEvent.type(
      screen.getByPlaceholderText("https://api.acme.com/v1"),
      "https://api.open-meteo.com/v1",
    );
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() => expect(api.registerConnector).toHaveBeenCalled());
    const sent = vi.mocked(api.registerConnector).mock.calls[0][0];
    expect(sent).toHaveProperty("credential_prefix", "Bearer ");
    // The header keeps omit-when-empty: empty genuinely means the default header
    // name, with no second meaning to collide with.
    expect(sent).not.toHaveProperty("credential_header");
  });

  it("a cleared prefix sends the bare token, which an x-api-key vendor wants", async () => {
    // The case the old hint could only describe and never produce (061): clearing
    // the field sends `credential_prefix: ""` — a real value, meaning the bare
    // token — rather than vanishing into "untouched".
    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    show([host()]);

    await userEvent.click(await screen.findByLabelText(/REST API/));
    await userEvent.type(screen.getByPlaceholderText("jira"), "openmeteo");
    await userEvent.type(
      screen.getByPlaceholderText("https://api.acme.com/v1"),
      "https://api.open-meteo.com/v1",
    );
    await userEvent.clear(screen.getByLabelText(/Credential prefix/));
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() => expect(api.registerConnector).toHaveBeenCalled());
    const sent = vi.mocked(api.registerConnector).mock.calls[0][0];
    expect(sent).toHaveProperty("credential_prefix", "");
  });

  it("offers the MCP credential fields to nobody", async () => {
    show([host()]);

    expect(await screen.findByPlaceholderText("jira")).toBeInTheDocument();
    expect(screen.queryByPlaceholderText("x-api-key")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Add a header" }),
    ).not.toBeInTheDocument();
  });

  it("sets asserted identity at registration when it is ticked", async () => {
    // **Settable here on purpose** — the schema says so: *"settable at registration so a
    // connector born trusting a caller says so from its first administrative record"*.
    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    show([host()]);

    await userEvent.type(await screen.findByPlaceholderText("jira"), "jira");
    await userEvent.type(
      screen.getByPlaceholderText("https://mcp.acme.com/mcp"),
      "https://mcp.acme.com/mcp",
    );
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() =>
      expect(api.registerConnector).toHaveBeenCalledWith(
        expect.objectContaining({ allow_asserted_identity: true }),
      ),
    );
  });

  it("states the consequence beside the box rather than only labelling it", async () => {
    // 033's decision 8 posture is *verified or nothing*, and the failure mode of this field
    // is somebody ticking it without reading it. A two-word label is that failure.
    show([host()]);

    expect(
      await screen.findByText(/may name who it acts on behalf of without verification/),
    ).toBeInTheDocument();
    // And it points at the place a change gets its own record, so this form does not become
    // a second toggle.
    expect(
      screen.getByText(/change this later on the connector's page/),
    ).toBeInTheDocument();
  });

  it("says that adding a connector approves nothing, and what to do next", async () => {
    show([host()]);

    // The state a person is in for as long as it takes them to read a vendor's
    // documentation, and the one they will otherwise think is finished. 091 shortened
    // the sentence and kept it: it is one of the three on this page that exist because
    // somebody once got the opposite impression.
    expect(
      await screen.findByText(/Next: approve the tools you want to make available/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Tools are unavailable until approved/)).toBeInTheDocument();
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

describe("recipes — step 068", () => {
  it("offers the recipe chooser before any host is approved", async () => {
    // The chooser is what answers "which hosts do I approve", so gating it behind having
    // approved one would hide the answer behind the question.
    show([], [], [recipe()]);
    expect(await screen.findByText("Jira")).toBeInTheDocument();
    // …while the form itself stays gated, because registration genuinely cannot succeed.
    expect(screen.queryByPlaceholderText("jira")).not.toBeInTheDocument();
  });

  it("says plainly when a recipe has never been checked against the vendor", async () => {
    show([host()], [], [recipe()]);
    await userEvent.click(await screen.findByRole("radio", { name: /Jira/ }));
    expect(screen.getByText(/have not been verified/)).toBeInTheDocument();
    expect(screen.getByText(/You can edit every field below/)).toBeInTheDocument();
  });

  it("renders a checked recipe's date rather than a warning", async () => {
    show(
      [host()],
      [],
      [recipe({ staleness: "verified", verified_on: "2026-09-02", verified_by: "a@b.c" })],
    );
    await userEvent.click(await screen.findByRole("radio", { name: /Jira/ }));
    expect(screen.getByText("checked 2026-09-02")).toBeInTheDocument();
    expect(screen.queryByText(/have not been verified/)).not.toBeInTheDocument();
  });

  it("marks which of the hosts it needs are approved, and does not approve them", async () => {
    show([host()], [], [recipe()]);
    await userEvent.click(await screen.findByRole("radio", { name: /Jira/ }));

    // The `why` sentences are unique to the recipe block; the hostnames also appear in
    // the allowlist card above, which is the point of the whole layout.
    expect(screen.getByText("The MCP server itself.")).toBeInTheDocument();
    expect(screen.getByText("The OAuth token endpoint.")).toBeInTheDocument();
    expect(screen.getByText("approved")).toBeInTheDocument();
    expect(screen.getByText("not approved")).toBeInTheDocument();
    // Choosing a recipe approves nothing. The approve control is the form above, and
    // pressing it is a separate act by somebody who can make it.
    expect(api.approveHost).not.toHaveBeenCalled();
  });

  it("fills the form and sends the recipe's values with the recipe named", async () => {
    show([host()], [], [recipe()]);
    await userEvent.click(await screen.findByRole("radio", { name: /Jira/ }));

    expect(screen.getByDisplayValue("jira")).toBeInTheDocument();
    expect(screen.getByDisplayValue("https://mcp.acme.com/mcp")).toBeInTheDocument();
    expect(screen.getByDisplayValue("JIRA_TOKEN")).toBeInTheDocument();

    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    await userEvent.click(screen.getByRole("button", { name: /Register/i }));

    expect(api.registerConnector).toHaveBeenCalledWith(
      expect.objectContaining({
        connector_id: "jira",
        url: "https://mcp.acme.com/mcp",
        credential_env: "JIRA_TOKEN",
        from_recipe: "atlassian-jira",
      }),
    );
  });

  it("lets every pre-filled value be edited before registering", async () => {
    // Rule 1 in the UI: a recipe is a default, not a dependency. This is what makes a
    // stale recipe cost one form's worth of wrong values rather than a broken setup.
    show([host()], [], [recipe()]);
    await userEvent.click(await screen.findByRole("radio", { name: /Jira/ }));

    const url = screen.getByDisplayValue("https://mcp.acme.com/mcp");
    await userEvent.clear(url);
    await userEvent.type(url, "https://mcp.acme.com/v2/mcp");

    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    await userEvent.click(screen.getByRole("button", { name: /Register/i }));

    expect(api.registerConnector).toHaveBeenCalledWith(
      expect.objectContaining({ url: "https://mcp.acme.com/v2/mcp" }),
    );
  });

  it("sends no recipe when the form was filled by hand", async () => {
    show([host()], [], [recipe()]);
    await screen.findByText("Jira");

    await userEvent.type(screen.getByPlaceholderText("jira"), "mine");
    await userEvent.type(
      screen.getByPlaceholderText("https://mcp.acme.com/mcp"),
      "https://mcp.acme.com/x",
    );
    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    await userEvent.click(screen.getByRole("button", { name: /Register/i }));

    expect(api.registerConnector).toHaveBeenCalledWith(
      expect.not.objectContaining({ from_recipe: expect.anything() }),
    );
  });

  it("says a recipe proposed tools and approved none of them", async () => {
    show(
      [host()],
      [],
      [
        recipe({
          tools: [
            {
              remote_name: "chat",
              effect: "write",
              identity: "service",
              resources: [],
              local_name: null,
              max_response_bytes: null,
              description: "",
              note: "",
              redact_args: [],
              binding: null,
            },
          ],
        }),
      ],
    );
    await userEvent.click(await screen.findByRole("radio", { name: /Jira/ }));
    expect(
      screen.getByText(/Approve each one on the connector's page after registering/),
    ).toBeInTheDocument();
  });

  it("keeps registration usable when the catalogue cannot be loaded", async () => {
    // A failed catalogue is not a failed page: the whole feature is a convenience over a
    // form somebody can fill in by hand.
    vi.mocked(api.listHosts).mockResolvedValue([host()]);
    vi.mocked(api.listConnectors).mockResolvedValue([]);
    vi.mocked(api.listRecipes).mockRejectedValue(new ApiError(500, "the catalogue is unreadable"));
    render(
      <MemoryRouter>
        <ConnectorsPage />
      </MemoryRouter>,
    );
    expect(
      await screen.findByText(/You can still register a connector below/),
    ).toBeInTheDocument();
    expect(screen.getByPlaceholderText("jira")).toBeInTheDocument();
  });
});

describe("a REST recipe and the empty-prefix trap — 061, via 068", () => {
  function restRecipe(): Recipe {
    return recipe({
      id: "anthropic-messages",
      name: "Anthropic",
      hosts: [{ host: "mcp.acme.com", why: "The Messages API." }],
      connector: {
        connector_id: "anthropic",
        url: "https://mcp.acme.com",
        kind: "rest",
        credential_env: "ANTHROPIC_BROKERED_KEY",
        // The two values 061 established must not collapse: `""` is a REAL prefix
        // meaning *the bare token*, and it is what an x-api-key vendor wants.
        credential_header: "x-api-key",
        credential_prefix: "",
        headers: { "anthropic-version": "2023-06-01" },
        description: "Anthropic, the Messages API",
      },
      oauth: null,
    });
  }

  it("sends an empty prefix as a value, not as an absence", async () => {
    // The failure 061 fixed, reachable again through a recipe: `?? "Bearer "` must fall
    // back on null/undefined and NOT on "", or every x-api-key connector 401s.
    show([host()], [], [restRecipe()]);
    await userEvent.click(await screen.findByRole("radio", { name: /Anthropic/ }));

    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    await userEvent.click(screen.getByRole("button", { name: /Register/i }));

    expect(api.registerConnector).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: "rest",
        credential_header: "x-api-key",
        credential_prefix: "",
        headers: { "anthropic-version": "2023-06-01" },
      }),
    );
  });

  it("falls back to Bearer when a recipe states no prefix", async () => {
    const noPrefix = restRecipe();
    noPrefix.connector.credential_prefix = null;
    noPrefix.connector.credential_header = null;
    show([host()], [], [noPrefix]);
    await userEvent.click(await screen.findByRole("radio", { name: /Anthropic/ }));

    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    await userEvent.click(screen.getByRole("button", { name: /Register/i }));

    expect(api.registerConnector).toHaveBeenCalledWith(
      expect.objectContaining({ credential_prefix: "Bearer " }),
    );
    // Omitted rather than sent empty: an empty header name genuinely means the default,
    // with no second meaning to collide with.
    expect(api.registerConnector).toHaveBeenCalledWith(
      expect.not.objectContaining({ credential_header: expect.anything() }),
    );
  });

  it("switches the form to the REST shape a recipe declares", async () => {
    show([host()], [], [restRecipe()]);
    await userEvent.click(await screen.findByRole("radio", { name: /Anthropic/ }));
    // The credential fields exist only for REST, so their presence is the evidence the
    // kind came across.
    expect(screen.getByPlaceholderText("x-api-key")).toBeInTheDocument();
  });
});


// --- 070: a credential the platform does not hold ------------------------------------

it("sends a vault reference instead of a variable, and never both", async () => {
  // The server refuses both being set, so the form offers a **choice** rather than two
  // boxes — a form that can express a refusal is a form somebody will fill in that way.
  vi.mocked(api.registerConnector).mockResolvedValue(connector());
  show([host()]);

  await userEvent.type(await screen.findByPlaceholderText("jira"), "jira");
  await userEvent.type(
    screen.getByPlaceholderText("https://mcp.acme.com/mcp"),
    "https://mcp.acme.com/mcp",
  );
  // Before the choice, so the switch has something to leave behind if it is going to.
  await userEvent.type(screen.getByPlaceholderText("JIRA_TOKEN"), "JIRA_TOKEN");

  await userEvent.click(
    screen.getByRole("radio", { name: /Vault reference/ }),
  );
  await userEvent.type(
    screen.getByPlaceholderText("op://Engineering/Jira/credential"),
    "op://Engineering/Jira/credential",
  );
  await userEvent.click(screen.getByRole("button", { name: "Register" }));

  await waitFor(() =>
    expect(api.registerConnector).toHaveBeenCalledWith(
      expect.objectContaining({
        // The typed variable is gone rather than carried along, because the unchosen
        // field is sent EMPTY rather than omitted.
        credential_env: "",
        credential_ref: "op://Engineering/Jira/credential",
      }),
    ),
  );
});

it("shows one credential box at a time, so both can never be typed", async () => {
  show([host()]);

  expect(await screen.findByPlaceholderText("JIRA_TOKEN")).toBeInTheDocument();
  expect(
    screen.queryByPlaceholderText("op://Engineering/Jira/credential"),
  ).not.toBeInTheDocument();

  await userEvent.click(screen.getByRole("radio", { name: /Vault reference/ }));

  expect(screen.queryByPlaceholderText("JIRA_TOKEN")).not.toBeInTheDocument();
  expect(
    screen.getByPlaceholderText("op://Engineering/Jira/credential"),
  ).toBeInTheDocument();
});

it("says what a vault-held credential costs, on the form where it is chosen", async () => {
  // The cost is real — one to three requests to somebody else's service on every call,
  // and a connector that stops working while their vault is down. An option that
  // presented it as a free upgrade would be the form making a promise the runtime
  // cannot keep.
  show([host()]);
  const option = await screen.findByRole("radio", { name: /Vault reference/ });
  expect(option.closest("label")).toHaveTextContent(/on every call/);
  expect(option.closest("label")).toHaveTextContent(/while the vault is unavailable/);
});


// --- 091: the page a stranger reads ---------------------------------------------------

describe("connectors, as cards", () => {
  it("gives every connector a card, a mark and a status word", async () => {
    show([host()], [connector({ vetted: 3 })]);

    const card = (await screen.findByText("jira")).closest(".conn-card") as HTMLElement;
    // The mark is decoration beside a name that is already there, so it announces
    // nothing — but it is drawn, and it is drawn without fetching anything.
    expect(card.querySelector(".brandmark")).toHaveAttribute("aria-hidden", "true");
    expect(card.querySelector("img")).toBeNull();
    expect(card).toHaveTextContent("Ready");
    expect(card).toHaveTextContent(/3 tools approved/);
  });

  it("says the plain thing about a connector nobody has finished", async () => {
    show([host()], [connector()]);

    const card = (await screen.findByText("jira")).closest(".conn-card") as HTMLElement;
    expect(card).toHaveTextContent("Needs setup");
    expect(card).toHaveTextContent(/Open it to discover and approve tools/);
  });

  it("answers an empty list as a fact rather than as a fault", async () => {
    show([host()], []);

    expect(await screen.findByText("No connectors")).toBeInTheDocument();
    expect(screen.getByText(/Add one below/)).toBeInTheDocument();
  });
});

describe("the badge and the sentence", () => {
  // Two functions, three conditions, one order. They are separate because a badge and a
  // sentence are read at different speeds by different people; they must never disagree.
  it("agrees with describe() on every branch", () => {
    const paused = connector({ host_allowed: false, vetted: 3 });
    expect(status(paused).word).toBe("Paused");
    expect(describeConnector(paused)).toContain("cannot connect until the host is approved again");

    const bare = connector({ vetted: 0 });
    expect(status(bare).word).toBe("Needs setup");
    expect(describeConnector(bare)).toContain("No tools approved yet");

    const ready = connector({ vetted: 2 });
    expect(status(ready).word).toBe("Ready");
    expect(describeConnector(ready)).toContain("2 tools approved");
  });

  it("leads with the address, not with the tool count, when a host was revoked", () => {
    // The state that looks perfectly healthy and is not: the connector is intact and
    // simply cannot dial. A green badge over it would be the page lying at a glance.
    expect(status(connector({ host_allowed: false, vetted: 9 })).tone).toBe("warn");
  });
});

describe("allowing an address from where it is asked for", () => {
  it("posts the same request the allowlist form posts, and reloads", async () => {
    vi.mocked(api.approveHost).mockResolvedValue({
      host: "auth.atlassian.com",
      note: "The OAuth token endpoint.",
      warning: "",
    });
    show([host()], [], [recipe()]);
    await userEvent.click(await screen.findByRole("radio", { name: /Jira/ }));

    // One button, on the one host of the two that is not approved yet.
    const allow = screen.getByRole("button", { name: "Allow" });
    await userEvent.click(allow);

    await waitFor(() =>
      expect(api.approveHost).toHaveBeenCalledWith(
        "auth.atlassian.com",
        "The OAuth token endpoint.",
      ),
    );
    // The allowlist below is re-read, so the badge beside the address and the table at
    // the bottom of the page cannot disagree about what just happened.
    await waitFor(() => expect(api.listHosts).toHaveBeenCalledTimes(2));
  });

  it("offers nothing to press on an address that is already allowed", async () => {
    show([host()], [], [recipe()]);
    await userEvent.click(await screen.findByRole("radio", { name: /Jira/ }));

    expect(screen.getAllByRole("button", { name: "Allow" })).toHaveLength(1);
    expect(screen.getByText("approved")).toBeInTheDocument();
  });

  it("offers it to nobody the server would refuse", async () => {
    // `your_role`'s lesson, reaching the second control that has to learn it: a button
    // that refuses the person who pressed it reads as a bug where its absence reads as a
    // rule. The chooser still renders — it is what answers "which addresses do I need".
    vi.mocked(api.listHosts).mockRejectedValue(new ApiError(403, "not an administrator"));
    vi.mocked(api.listConnectors).mockResolvedValue([]);
    vi.mocked(api.listRecipes).mockResolvedValue([recipe()]);
    render(
      <MemoryRouter>
        <ConnectorsPage />
      </MemoryRouter>,
    );

    await userEvent.click(await screen.findByRole("radio", { name: /Jira/ }));
    expect(screen.queryByRole("button", { name: "Allow" })).not.toBeInTheDocument();
  });

  it("shows the server's refusal beside the address rather than swallowing it", async () => {
    vi.mocked(api.approveHost).mockRejectedValue(
      new ApiError(400, "'auth.atlassian.com/x' contains a path."),
    );
    show([host()], [], [recipe()]);
    await userEvent.click(await screen.findByRole("radio", { name: /Jira/ }));
    await userEvent.click(screen.getByRole("button", { name: "Allow" }));

    expect(await screen.findByText(/contains a path/)).toBeInTheDocument();
  });
});

describe("what 091 folded away, and what it refused to", () => {
  it("keeps the asserted-identity control in plain sight", async () => {
    // The one control on this page whose failure mode is being ticked unread. A pass
    // whose brief was "less overwhelming" folding *that* away would be the wrong half of
    // the form getting shorter.
    show([host()]);

    const box = await screen.findByRole("checkbox");
    expect(box.closest("details")).toBeNull();
  });

  it("puts the API-vendor credential scheme behind a disclosure", async () => {
    show([host()]);

    await userEvent.click(await screen.findByLabelText(/REST API/));
    // Still reachable, still sent, still REST-only — just not in the way of somebody
    // registering an MCP server, which is most people most of the time.
    expect(screen.getByPlaceholderText("x-api-key").closest("details")).not.toBeNull();
    expect(screen.getByLabelText(/Description/).closest("details")).not.toBeNull();
  });
});
