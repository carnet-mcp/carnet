/** The vetting screen, and the four things it must not get wrong.
 *
 * Most of this page is a form, and a form is not what is worth asserting. What is:
 *
 *   - **the argument names and their requiredness are on screen.** That is the entire
 *     reason `--discover` exists and the one part of vetting a person cannot guess. A
 *     screen that showed tool names and descriptions would look complete while leaving
 *     the actual difficulty exactly where it was.
 *   - **a `refuse` finding blocks, and looks like it blocks.** `vet_tool` approves nothing
 *     further on a drifted connector, so a page that rendered drift as a note beside a
 *     working form would offer a button whose every press is a 400.
 *   - **the client secret is a password field and is never echoed back** — not even
 *     masked, because `••••••` implies the value is retrievable and it is not.
 *   - **the server's refusals are rendered verbatim.** Every one of them is written for
 *     the person filling in this form, and a paraphrase would lose the half that says
 *     what to do instead.
 */

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return {
    ...actual,
    api: {
      getConnector: vi.fn(),
      discover: vi.fn(),
      vetTool: vi.fn(),
      configureOAuth: vi.fn(),
      removeOAuth: vi.fn(),
      setAssertedIdentity: vi.fn(),
    },
  };
});

import ConnectorDetailPage from "./ConnectorDetailPage";
import { api, ApiError } from "../../lib/api";
import type { ConnectorDetail, DiscoveryResult, OAuthApp, VettedTool } from "../../lib/types";

function connector(overrides: Partial<ConnectorDetail> = {}): ConnectorDetail {
  return {
    connector_id: "jira",
    description: "Jira, issues only",
    transport: "http",
    url: "https://mcp.acme.com/mcp",
    credential_env: "JIRA_TOKEN",
    credential_ref: "",
    vetted: 0,
    writes: 0,
    host: "mcp.acme.com",
    host_allowed: true,
    oauth: null,
    allow_asserted_identity: false,
    tools: [],
    ...overrides,
  };
}

function oauthApp(overrides: Partial<OAuthApp> = {}): OAuthApp {
  return {
    connector_id: "jira",
    authorize_endpoint: "https://auth.acme.com/authorize",
    token_endpoint: "https://auth.acme.com/token",
    revoke_endpoint: "",
    client_id: "client-abc",
    scopes: ["offline_access"],
    scope_notes: {},
    authorize_params: {},
    configured_by: "user:u_9311",
    configured_at: "2026-08-09T10:00:00+00:00",
    ...overrides,
  };
}

/** A whole `VettedTool`, on `Partial<T>`'s argument — 035f's finding 2, where a hand-rolled
 *  fixture carrying only the fields one component read type-checked fine and hid the next
 *  field the same way. `note` and `max_response_bytes` had been on this type since 12c and
 *  no fixture had ever set either, which is part of why nothing noticed the table dropped
 *  them. */
function vetted(overrides: Partial<VettedTool> = {}): VettedTool {
  return {
    name: "jira_list_issues",
    remote_name: "list_issues",
    description: "List issues in a project.",
    note: "",
    effect: "read",
    identity: "service",
    resources: [],
    max_response_bytes: null,
    vetted_by: "user:u_9311",
    vetted_at: "2026-08-09T10:00:00+00:00",
    server_name: "jira-mcp-server",
    server_version: "v2.3.0",
    ...overrides,
  };
}

const DISCOVERED: DiscoveryResult = {
  server: "jira-mcp-server v2.3.0",
  tools: [
    {
      name: "create_issue",
      description: "Create an issue in a Jira project.",
      arguments: [
        { name: "projectKey", type: "string", required: true },
        { name: "description", type: "string", required: false },
      ],
      vetted: false,
      local_name: "jira_create_issue",
    },
  ],
  findings: [],
};

function show(detail: ConnectorDetail = connector()) {
  vi.mocked(api.getConnector).mockResolvedValue(detail);
  return render(
    <MemoryRouter initialEntries={["/admin/connectors/jira"]}>
      <Routes>
        <Route path="/admin/connectors/:connectorId" element={<ConnectorDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(api.getConnector).mockReset();
  vi.mocked(api.discover).mockReset();
  vi.mocked(api.vetTool).mockReset();
  vi.mocked(api.configureOAuth).mockReset();
  vi.mocked(api.removeOAuth).mockReset();
  vi.mocked(api.setAssertedIdentity).mockReset();
});

describe("on behalf of (033c)", () => {
  it("states the resting posture and flips it as one deliberate action", async () => {
    vi.mocked(api.setAssertedIdentity).mockResolvedValue(
      connector({ allow_asserted_identity: true }),
    );
    show(connector());

    // Off is the posture, and the sentence says what IS accepted rather than only
    // what is not.
    expect(
      await screen.findByText(/on-behalf-of claim is accepted/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Asserted claims are denied for this connector's tools/),
    ).toBeInTheDocument();

    await userEvent.click(
      await screen.findByRole("button", { name: "Accept asserted identity" }),
    );

    expect(api.setAssertedIdentity).toHaveBeenCalledWith("jira", true);
  });

  it("says what an enabled assertion is worth", async () => {
    show(connector({ allow_asserted_identity: true }));

    expect(
      await screen.findByText(/who it acts on behalf of, without verification/),
    ).toBeInTheDocument();
    expect(
      await screen.findByRole("button", { name: "Stop accepting asserted identity" }),
    ).toBeInTheDocument();
  });
});

describe("looking at the server", () => {
  it("contacts nothing until somebody asks", async () => {
    show(connector());

    expect(await screen.findByText("https://mcp.acme.com/mcp")).toBeInTheDocument();
    // The whole page above the fold renders from the stored manifest. That is migration
    // 018's argument: a page about what somebody approved must not be down whenever a
    // customer's server is.
    expect(api.discover).not.toHaveBeenCalled();
  });

  it("shows each argument's name and whether it is required", async () => {
    vi.mocked(api.discover).mockResolvedValue(DISCOVERED);
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Discover" }));

    // **The reason this screen exists.** `resources` needs the exact argument name this
    // server uses, and `required` decides whether the tool is scopeable at all — an
    // optional argument that widens reach when absent is invisible without it.
    const line = await screen.findByText(/projectKey \(string, required\)/);
    expect(line).toHaveTextContent("description (string, optional)");
    expect(screen.getByText("jira-mcp-server v2.3.0")).toBeInTheDocument();
  });

  it("renders a server that did not answer as the transport's own sentence", async () => {
    vi.mocked(api.discover).mockRejectedValue(
      new ApiError(502, "could not reach https://mcp.acme.com/mcp: connection refused"),
    );
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Discover" }));

    // A 502 is the customer's own server, not our outage and not their mistake. The
    // sentence names the host, which is what tells them which of the three it was.
    expect(await screen.findByText(/connection refused/)).toBeInTheDocument();
  });
});

describe("drift", () => {
  it("blocks the forms and says why, rather than noting it beside them", async () => {
    vi.mocked(api.discover).mockResolvedValue({
      ...DISCOVERED,
      findings: [
        { severity: "refuse", message: "search_issues is vetted and no longer advertised" },
      ],
    });
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Discover" }));

    expect(
      await screen.findByText(/search_issues is vetted and no longer advertised/),
    ).toBeInTheDocument();
    // `vet_tool` refuses everything on a drifted connector, so a form here would be a
    // button whose every press is a 400.
    expect(screen.queryByRole("button", { name: "Approve…" })).not.toBeInTheDocument();
  });

  it("reports a newly advertised tool without offering to adopt it", async () => {
    vi.mocked(api.discover).mockResolvedValue({
      ...DISCOVERED,
      findings: [{ severity: "report", message: "delete_project is advertised and not vetted" }],
    });
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Discover" }));

    expect(await screen.findByText(/delete_project is advertised/)).toBeInTheDocument();
    // A report does not block: the forms are still there, because approving a tool is
    // exactly what somebody would now want to do.
    expect(screen.getByRole("button", { name: "Approve…" })).toBeInTheDocument();
  });
});

describe("approving a tool", () => {
  it("sends a structured resource rather than the CLI's TYPE=ARG string", async () => {
    vi.mocked(api.discover).mockResolvedValue(DISCOVERED);
    vi.mocked(api.vetTool).mockResolvedValue({
      local_name: "jira_create_issue",
      remote_name: "create_issue",
      effect: "write",
      identity: "service",
      resources: ["jira.project"],
      server: "jira-mcp-server v2.3.0",
      actor: "user:u_9311",
    });
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Discover" }));
    await userEvent.click(await screen.findByRole("button", { name: "Approve…" }));
    await userEvent.selectOptions(screen.getByLabelText(/Effect/), "write");
    await userEvent.click(screen.getByRole("button", { name: "Add a resource" }));
    await userEvent.type(screen.getByPlaceholderText("jira.project"), "jira.project");
    // **The argument is picked from the discovered names, not typed.** The commonest way
    // to get vetting wrong is naming an argument the server does not have, and a list of
    // the ones it does have makes that unspellable rather than merely refused.
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "" }), "projectKey");
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() =>
      expect(api.vetTool).toHaveBeenCalledWith("jira", "create_issue", {
        effect: "write",
        identity: "service",
        resources: [{ type: "jira.project", args: ["projectKey"] }],
        note: "",
        local_name: null,
        // 035g. **Null is the value, not an omission being tolerated**: it means *this
        // deployment's `MAX_RESPONSE_BYTES`*, which is right for nearly every tool. The
        // inverse of `max_tokens: null`, where a stored null is the hazard.
        max_response_bytes: null,
      }),
    );
    expect(
      await screen.findByText(/Approved as jira_create_issue, against jira-mcp-server/),
    ).toBeInTheDocument();
  });

  it("renders the server's refusal verbatim", async () => {
    vi.mocked(api.discover).mockResolvedValue(DISCOVERED);
    vi.mocked(api.vetTool).mockRejectedValue(
      new ApiError(
        400,
        "tool 'jira_create_issue' is a write but declares no resources. A write to " +
          "something policy cannot name is unscopeable — give it a resource, or mark it " +
          "read if it genuinely changes nothing.",
      ),
    );
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Discover" }));
    await userEvent.click(await screen.findByRole("button", { name: "Approve…" }));
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    // Verbatim, because the half after the dash is what to do instead — which is the
    // whole difference between this and the 500 it used to be.
    expect(await screen.findByText(/mark it read if it genuinely changes nothing/)).toBeInTheDocument();
  });
});

describe("the OAuth app", () => {
  it("takes the secret in a password field and never shows one back", async () => {
    vi.mocked(api.configureOAuth).mockResolvedValue({
      app: oauthApp(),
      redirect_uri: "https://runtime.acme.com/connect/callback",
      warnings: [],
    });
    show();

    await userEvent.click(
      await screen.findByRole("button", { name: "Set up OAuth app" }),
    );

    const secret = screen.getByLabelText(/Client secret/);
    expect(secret).toHaveAttribute("type", "password");

    await userEvent.type(screen.getByLabelText(/Authorize endpoint/), "https://auth.acme.com/authorize");
    await userEvent.type(screen.getByLabelText(/Token endpoint/), "https://auth.acme.com/token");
    await userEvent.type(screen.getByLabelText(/Client ID/), "client-abc");
    await userEvent.type(secret, "MARKER-CLIENT-SECRET-e3f1");
    await userEvent.click(screen.getByRole("button", { name: "Save OAuth app" }));

    // The one real onboarding ask, rendered where the person who must do it is standing.
    expect(
      await screen.findByText("https://runtime.acme.com/connect/callback"),
    ).toBeInTheDocument();
    // And the secret is gone from the page the instant it is accepted.
    expect(document.body.textContent).not.toContain("MARKER-CLIENT-SECRET-e3f1");
  });

  it("says stored rather than showing a masked secret", async () => {
    show(connector({ oauth: oauthApp() }));

    expect(await screen.findByText("stored")).toBeInTheDocument();
    // **Not `••••••`.** A masked echo implies the value can be read back, and nothing in
    // this system can read it back — not this screen, not the API, not an administrator.
    expect(document.body.textContent).not.toContain("•");
  });

  it("refuses to offer one on a connector that could never use it", async () => {
    show(connector({ transport: "stdio", url: "" }));

    expect(
      await screen.findByText(/An OAuth app is not available for it/),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Set up OAuth app" }),
    ).not.toBeInTheDocument();
  });
});

describe("a host that was revoked underneath a connector", () => {
  it("says the registration and the vetting are still there", async () => {
    show(connector({ host_allowed: false, vetted: 3 }));

    // The assumption this exists to correct is that revoking a host deleted the
    // connector. It did not, and believing it did means believing a customer's
    // integration is gone when the row is waiting for the host to come back.
    expect(await screen.findByText(/mcp.acme.com is not approved/)).toBeInTheDocument();
    expect(
      screen.getByText(/Its registration and approved tools are kept/),
    ).toBeInTheDocument();
  });
});

describe("the response limit (035g)", () => {
  async function openTheForm() {
    vi.mocked(api.discover).mockResolvedValue(DISCOVERED);
    show();
    await userEvent.click(await screen.findByRole("button", { name: "Discover" }));
    await userEvent.click(await screen.findByRole("button", { name: "Approve…" }));
  }

  it("sends a size when one is given", async () => {
    vi.mocked(api.vetTool).mockResolvedValue({
      local_name: "jira_create_issue",
      remote_name: "create_issue",
      effect: "read",
      identity: "service",
      resources: [],
      server: "jira-mcp-server v2.3.0",
      actor: "user:u_9311",
    });
    await openTheForm();

    await userEvent.type(screen.getByLabelText(/Response limit/), "200000");
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() =>
      expect(api.vetTool).toHaveBeenCalledWith(
        "jira",
        "create_issue",
        expect.objectContaining({ max_response_bytes: 200000 }),
      ),
    );
  });

  it("refuses a zero itself, and sends nothing", async () => {
    // **The one place this page pre-empts a refusal rather than rendering one.** A stored
    // zero reaches `broker._bound_response` as the cap outright, so the tool refuses every
    // response it will ever return and tells the model to narrow a request that narrowing
    // cannot fix. The server bound is `Field(gt=0)` and therefore a **422**, whose `detail`
    // is a list of field errors — collapsed by `readProblem` to one generic sentence that
    // names no field, in the box where every other refusal on this page is a paragraph
    // saying what to do instead.
    await openTheForm();

    await userEvent.type(screen.getByLabelText(/Response limit/), "0");
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    expect(
      await screen.findByText(/denies every response/),
    ).toBeInTheDocument();
    // A refusal and not a warning: nothing was sent, so nothing was stored.
    expect(api.vetTool).not.toHaveBeenCalled();
  });

  it("refuses a negative one the same way", async () => {
    await openTheForm();

    await userEvent.type(screen.getByLabelText(/Response limit/), "-5");
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    await screen.findByText(/denies every response/);
    expect(api.vetTool).not.toHaveBeenCalled();
  });

  it("refuses a fraction and a number the browser has already rounded", async () => {
    // Both are 422s at the server — the integer type and `le` on the BIGINT — and
    // therefore both are the one generic sentence. A rounded number is the worse of the
    // two: it would store a ceiling nobody typed.
    await openTheForm();

    const box = screen.getByLabelText(/Response limit/);
    await userEvent.type(box, "1.5");
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));
    await screen.findByText(/whole number of bytes/);

    await userEvent.clear(box);
    await userEvent.type(box, "99999999999999999999");
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));
    await screen.findByText(/whole number of bytes/);

    expect(api.vetTool).not.toHaveBeenCalled();
  });

  it("does not name a number a screen cannot know", async () => {
    // `config.MAX_RESPONSE_BYTES` is a fact about the deployment and is on no response, so
    // this hint would be guessing if it said 64 KiB. 035e's `TokenSpend.ceiling` argument at
    // a different field.
    await openTheForm();

    const hint = screen.getByLabelText(/Response limit/);
    expect(hint).toHaveAccessibleName(/the deployment default/);
    expect(hint).not.toHaveAccessibleName(/64/);
  });
});

describe("what an approval recorded (035g)", () => {
  it("shows the note somebody wrote at approval time", async () => {
    // It reaches the grantee already — `ToolSummary` carries it and the tool picker
    // renders it — and did not reach this table, which is where approvals are audited. The
    // person who wrote it and the person reviewing it were the two who could not see it.
    show(connector({ vetted: 1, tools: [vetted({ note: "Finance owns this project." })] }));

    expect(await screen.findByText("Finance owns this project.")).toBeInTheDocument();
  });

  it("shows a limit as a size, and says denied rather than truncated", async () => {
    show(connector({ vetted: 1, tools: [vetted({ max_response_bytes: 200000 })] }));

    expect(await screen.findByText(/195.3 kB are denied/)).toBeInTheDocument();
  });

  it("does not render a note that is only whitespace", async () => {
    // The form trims what it sends; `--note "   "` does not, and a blank paragraph under a
    // row reads as a rendering fault rather than as an empty field.
    show(connector({ vetted: 1, tools: [vetted({ note: "   " })] }));

    await screen.findByText("jira_list_issues");
    expect(document.querySelectorAll("tbody tr")).toHaveLength(1);
  });

  it("says nothing per row when there is nothing to say", async () => {
    // A line saying *no note* on every row would bury the rows that have one, and a ceiling
    // column would be six empty cells with one number in it.
    show(connector({ vetted: 1, tools: [vetted()] }));

    await screen.findByText("jira_list_issues");
    expect(screen.queryByText(/Responses over .* are denied/)).not.toBeInTheDocument();
    // The row still says everything it said before.
    expect(screen.getByText(/user:u_9311, against jira-mcp-server/)).toBeInTheDocument();
  });
});

describe("scope notes survive a re-save (068 review)", () => {
  const described = () =>
    oauthApp({
      scopes: ["read:jira-work", "write:jira-work", "offline_access"],
      scope_notes: {
        "read:jira-work": {
          name: "Read issues",
          description: "Lets an agent search and read issues.",
          access: "read",
        },
        "write:jira-work": {
          name: "Edit issues",
          description: "Lets an agent open, edit and transition issues.",
          access: "write",
        },
      },
    });

  it("rotating the client secret keeps every note", async () => {
    vi.mocked(api.configureOAuth).mockResolvedValue({
      app: described(),
      redirect_uri: "https://runtime.acme.com/connect/callback",
      warnings: [],
    });
    show(connector({ oauth: described() }));

    await userEvent.click(await screen.findByRole("button", { name: "Replace" }));
    // The form says the notes are there, since it has no box to show them in.
    expect(screen.getByText(/2 scopes carry a description shown at consent/)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText(/Client secret/), "rotated-secret");
    await userEvent.click(screen.getByRole("button", { name: "Save OAuth app" }));

    await waitFor(() =>
      expect(api.configureOAuth).toHaveBeenCalledWith(
        "jira",
        expect.objectContaining({
          scopes: ["read:jira-work", "write:jira-work", "offline_access"],
          scope_notes: described().scope_notes,
        }),
      ),
    );
  });

  it("dropping a scope drops its note rather than sending the server a 400", async () => {
    vi.mocked(api.configureOAuth).mockResolvedValue({
      app: described(),
      redirect_uri: "https://runtime.acme.com/connect/callback",
      warnings: [],
    });
    show(connector({ oauth: described() }));

    await userEvent.click(await screen.findByRole("button", { name: "Replace" }));
    const scopes = screen.getByLabelText(/Scopes/);
    await userEvent.clear(scopes);
    await userEvent.type(scopes, "read:jira-work offline_access");
    await userEvent.type(screen.getByLabelText(/Client secret/), "rotated-secret");
    await userEvent.click(screen.getByRole("button", { name: "Save OAuth app" }));

    await waitFor(() =>
      expect(api.configureOAuth).toHaveBeenCalledWith(
        "jira",
        expect.objectContaining({
          scopes: ["read:jira-work", "offline_access"],
          scope_notes: { "read:jira-work": described().scope_notes["read:jira-work"] },
        }),
      ),
    );
  });
});

describe("authorize parameters (035g)", () => {
  it("sends a name and a value the provider mandates", async () => {
    vi.mocked(api.configureOAuth).mockResolvedValue({
      app: oauthApp({ authorize_params: { audience: "api.atlassian.com" } }),
      redirect_uri: "https://runtime.acme.com/connect/callback",
      warnings: [],
    });
    show();

    await userEvent.click(
      await screen.findByRole("button", { name: "Set up OAuth app" }),
    );
    await userEvent.type(
      screen.getByLabelText(/Authorize endpoint/),
      "https://auth.acme.com/authorize",
    );
    await userEvent.type(
      screen.getByLabelText(/Token endpoint/),
      "https://auth.acme.com/token",
    );
    await userEvent.type(screen.getByLabelText(/Client ID/), "client-abc");
    await userEvent.type(screen.getByLabelText(/Client secret/), "s3cret");
    await userEvent.click(screen.getByRole("button", { name: "Add a parameter" }));
    await userEvent.type(screen.getByPlaceholderText("audience"), "audience");
    await userEvent.type(
      screen.getByPlaceholderText("api.atlassian.com"),
      "api.atlassian.com",
    );
    await userEvent.click(screen.getByRole("button", { name: "Save OAuth app" }));

    await waitFor(() =>
      expect(api.configureOAuth).toHaveBeenCalledWith(
        "jira",
        expect.objectContaining({
          authorize_params: { audience: "api.atlassian.com" },
        }),
      ),
    );
  });

  it("drops a row nobody named rather than making it the server's 400", async () => {
    vi.mocked(api.configureOAuth).mockResolvedValue({
      app: oauthApp(),
      redirect_uri: "https://runtime.acme.com/connect/callback",
      warnings: [],
    });
    show();

    await userEvent.click(
      await screen.findByRole("button", { name: "Set up OAuth app" }),
    );
    await userEvent.type(
      screen.getByLabelText(/Authorize endpoint/),
      "https://auth.acme.com/authorize",
    );
    await userEvent.type(
      screen.getByLabelText(/Token endpoint/),
      "https://auth.acme.com/token",
    );
    await userEvent.type(screen.getByLabelText(/Client ID/), "client-abc");
    await userEvent.type(screen.getByLabelText(/Client secret/), "s3cret");
    await userEvent.click(screen.getByRole("button", { name: "Add a parameter" }));
    await userEvent.click(screen.getByRole("button", { name: "Save OAuth app" }));

    await waitFor(() =>
      expect(api.configureOAuth).toHaveBeenCalledWith(
        "jira",
        expect.objectContaining({ authorize_params: {} }),
      ),
    );
  });

  it("renders the server's refusal of a reserved name verbatim, paragraph and all", async () => {
    // **The sentence is the security design.** A paraphrase — "that parameter is reserved" —
    // loses the half that explains why the platform will not let somebody do the thing they
    // just tried, and this is the refusal in the whole API most worth reading.
    vi.mocked(api.configureOAuth).mockRejectedValue(
      new ApiError(
        400,
        "'state' is built by the consent flow itself and may not be set here. It is the " +
          "only thing binding a provider's callback to the person who started it — the " +
          "callback carries no token, so a fixed or guessable value makes every consent " +
          "flow in this tenant forgeable.",
      ),
    );
    show();

    await userEvent.click(
      await screen.findByRole("button", { name: "Set up OAuth app" }),
    );
    await userEvent.type(
      screen.getByLabelText(/Authorize endpoint/),
      "https://auth.acme.com/authorize",
    );
    await userEvent.type(
      screen.getByLabelText(/Token endpoint/),
      "https://auth.acme.com/token",
    );
    await userEvent.type(screen.getByLabelText(/Client ID/), "client-abc");
    await userEvent.type(screen.getByLabelText(/Client secret/), "s3cret");
    await userEvent.click(screen.getByRole("button", { name: "Add a parameter" }));
    await userEvent.type(screen.getByPlaceholderText("audience"), "state");
    await userEvent.type(screen.getByPlaceholderText("api.atlassian.com"), "guessable");
    await userEvent.click(screen.getByRole("button", { name: "Save OAuth app" }));

    expect(
      await screen.findByText(/makes every consent flow in this tenant forgeable/),
    ).toBeInTheDocument();
  });

  it("puts each parameter on its own line, because a value may contain a space", async () => {
    // Found by 035g's comprehensive pass. The CLI joins these with a space, which is
    // unambiguous only while no value contains one — and a value is free text bound for a
    // URL. `prompt=consent please` in a joined line is two parameters or one, and nothing
    // tells them apart. Same family as 035f's comma-in-a-scope; the difference is that a
    // screen has the vertical space to fix it.
    show(
      connector({
        oauth: oauthApp({
          authorize_params: { prompt: "consent please", audience: "api.acme.com" },
        }),
      }),
    );

    expect(await screen.findByText("prompt=consent please")).toBeInTheDocument();
    expect(screen.getByText("audience=api.acme.com")).toBeInTheDocument();
  });

  it("shows the parameters a CLI already set", async () => {
    // The read half plan 035 does not mention. `--set-oauth --authorize-param` has existed
    // since migration 025 and this screen showed nothing, so an administrator could not see
    // that their Atlassian connector sends an audience — let alone which one.
    show(
      connector({
        oauth: oauthApp({
          authorize_params: { audience: "api.atlassian.com", prompt: "consent" },
        }),
      }),
    );

    expect(await screen.findByText("audience=api.atlassian.com")).toBeInTheDocument();
    expect(screen.getByText("prompt=consent")).toBeInTheDocument();
  });

  it("says none when there are none", async () => {
    show(connector({ oauth: oauthApp() }));

    // Scoped to its own row: the Revoke endpoint row above says "none" too, for a
    // different fact.
    const extra = (await screen.findByText("Extra parameters")).nextElementSibling;
    expect(extra).toHaveTextContent(/^none$/);
  });
});

describe("replacing an OAuth app (035g)", () => {
  it("opens with what is configured in it, because the PUT replaces wholesale", async () => {
    // **The defect this chunk would otherwise have widened.** The form opened empty, so
    // pressing Replace, filling the four required fields and saving silently cleared the
    // connector's scopes — and would now clear the authorize parameters too, which is the
    // field most likely to exist and least likely to be remembered.
    show(
      connector({
        oauth: oauthApp({
          scopes: ["read:issues", "offline_access"],
          authorize_params: { audience: "api.atlassian.com" },
        }),
      }),
    );

    await userEvent.click(await screen.findByRole("button", { name: "Replace" }));

    expect(screen.getByLabelText(/Scopes/)).toHaveValue("read:issues offline_access");
    expect(screen.getByPlaceholderText("audience")).toHaveValue("audience");
    expect(screen.getByPlaceholderText("api.atlassian.com")).toHaveValue(
      "api.atlassian.com",
    );
  });

  it("says the secret has to be typed again, and does not prefill one", async () => {
    // The honest version of *stored*, said at the moment it costs somebody something rather
    // than discovered at the submit button.
    show(connector({ oauth: oauthApp() }));

    await userEvent.click(await screen.findByRole("button", { name: "Replace" }));

    expect(screen.getByText(/replaces the whole OAuth app/)).toBeInTheDocument();
    expect(screen.getByLabelText(/Client secret/)).toHaveValue("");
  });

  it("offers no such sentence when there is nothing to replace", async () => {
    show(connector());

    await userEvent.click(
      await screen.findByRole("button", { name: "Set up OAuth app" }),
    );

    expect(screen.queryByText(/replaces the whole OAuth app/)).not.toBeInTheDocument();
  });
});

describe("approving again (035g's edge pass)", () => {
  const APPROVED = vetted({
    name: "jira_create_issue",
    remote_name: "create_issue",
    effect: "write",
    identity: "user",
    resources: [{ type: "jira.project" }],
    note: "Finance owns this project.",
    max_response_bytes: 200000,
  });

  async function reopen() {
    vi.mocked(api.discover).mockResolvedValue({
      ...DISCOVERED,
      tools: [{ ...DISCOVERED.tools[0], vetted: true }],
    });
    show(connector({ vetted: 1, tools: [APPROVED] }));
    await userEvent.click(await screen.findByRole("button", { name: "Discover" }));
    // An already-approved tool opens under a different verb than a new one.
    await userEvent.click(await screen.findByRole("button", { name: "Edit approval" }));
  }

  it("opens on the last review rather than on an empty form", async () => {
    // **`vet_tool` upserts the whole row**, so a blank *Approve again* form is
    // `ConsentFlow`'s wholesale-replace trap at the other write on this page — and worse,
    // because the defaults are `read`, `service` and no resources: pressing Approve again
    // on a scoped write and changing nothing downgraded it to an unscoped read and erased
    // the note. Found by 035g's edge pass asking what a re-vet that omits a field does.
    await reopen();

    expect(screen.getByLabelText(/Effect/)).toHaveValue("write");
    expect(screen.getByLabelText(/Acts as/)).toHaveValue("user");
    expect(screen.getByLabelText(/^Note/)).toHaveValue("Finance owns this project.");
    expect(screen.getByLabelText(/Response limit/)).toHaveValue(200000);
  });

  it("restores what it touches, and says why it cannot restore the argument", async () => {
    // `VettedTool.resources` is `{type}` alone and its comment says why: a client handed
    // the argument names would be invited to build a scope out of them. So the type comes
    // back, the picker is empty, and the screen says so rather than looking finished.
    await reopen();

    expect(screen.getByPlaceholderText("jira.project")).toHaveValue("jira.project");
    expect(screen.getByText(/Pick the argument for each again/)).toBeInTheDocument();
  });

  it("refuses a resource with no argument rather than dropping it silently", async () => {
    // The silent drop was reachable on a create too — type the type, forget the picker —
    // and it approved the tool without the scope somebody had just named.
    await reopen();

    await userEvent.click(screen.getByRole("button", { name: "Approve again" }));

    expect(
      await screen.findByText(/Every resource needs the argument that names it/),
    ).toBeInTheDocument();
    expect(api.vetTool).not.toHaveBeenCalled();
  });

  it("sends the whole review back when the argument is picked again", async () => {
    vi.mocked(api.vetTool).mockResolvedValue({
      local_name: "jira_create_issue",
      remote_name: "create_issue",
      effect: "write",
      identity: "user",
      resources: ["jira.project"],
      server: "jira-mcp-server v2.3.0",
      actor: "user:u_9311",
    });
    await reopen();

    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "" }),
      "projectKey",
    );
    await userEvent.click(screen.getByRole("button", { name: "Approve again" }));

    await waitFor(() =>
      expect(api.vetTool).toHaveBeenCalledWith("jira", "create_issue", {
        effect: "write",
        identity: "user",
        resources: [{ type: "jira.project", args: ["projectKey"] }],
        note: "Finance owns this project.",
        local_name: null,
        max_response_bytes: 200000,
      }),
    );
  });
});

/** Authoring a tool on a connector that describes nothing — step 047.
 *
 * The REST half had a route since 045a and no form at all, so a model provider was
 * registrable only from a shell — which is exactly the connector kind that takes an
 * agent's last private credential away, and the kind whose `redact_args` keeps prompts
 * out of an append-only table.
 *
 * What is worth asserting is not the form. It is that **the schema drives the pickers**:
 * `check_binding` refuses an unmapped argument with a good sentence, and a person can
 * only meet that sentence after typing everything. Reading the names out of the schema is
 * how this form offers what discovery buys the MCP one.
 */
describe("authoring a REST tool", () => {
  const rest = () =>
    connector({
      connector_id: "anthropic",
      transport: "rest",
      url: "https://api.anthropic.com/v1",
      credential_env: "ANTHROPIC_BROKERED_KEY",
      host: "api.anthropic.com",
    });

  const SCHEMA =
    '{"type":"object","properties":{"model":{"type":"string"},' +
    '"messages":{"type":"array"}},"required":["model","messages"]}';

  it("offers no Discover button, because there is nothing to ask", async () => {
    show(rest());

    expect(await screen.findByText("Author a tool")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Discover" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Look again" })).not.toBeInTheDocument();
  });

  it("keeps the authoring form off an MCP connector", async () => {
    show();

    expect(await screen.findByRole("button", { name: "Discover" })).toBeInTheDocument();
    expect(screen.queryByText("Author a tool")).not.toBeInTheDocument();
  });

  it("lists the schema's arguments so each one can be mapped", async () => {
    show(rest());

    await userEvent.type(await screen.findByPlaceholderText("chat"), "chat");
    await userEvent.click(screen.getByLabelText(/Input schema/));
    await userEvent.paste(SCHEMA);

    // Scoped to the mapping group: "model" also appears in the usage-map example, and
    // an unscoped match would pass on the placeholder rather than on the row.
    const group = (await screen.findByText("Argument mapping")).closest("div")!;
    expect(within(group).getByText("model")).toBeInTheDocument();
    expect(within(group).getByText("messages")).toBeInTheDocument();
  });

  it("refuses an unmapped argument here rather than after a round trip", async () => {
    show(rest());

    await userEvent.type(await screen.findByPlaceholderText("chat"), "chat");
    await userEvent.click(screen.getByLabelText(/Input schema/));
    await userEvent.paste(SCHEMA);
    await userEvent.type(screen.getByPlaceholderText("/repos/{owner}/{repo}/issues"), "/messages");
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    // The refusal names the arguments, which is what tells somebody what to map.
    expect(
      await screen.findByText(
        /model, messages are in the schema but not in the path, query or body/,
      ),
    ).toBeInTheDocument();
    expect(api.vetTool).not.toHaveBeenCalled();
  });

  it("sends the binding, the redaction and the usage map", async () => {
    vi.mocked(api.vetTool).mockResolvedValue({
      local_name: "anthropic_chat",
      remote_name: "chat",
      effect: "write",
      identity: "service",
      resources: [],
      server: "",
      actor: "user:u_9311",
    });
    show(rest());

    await userEvent.type(await screen.findByPlaceholderText("chat"), "chat");
    await userEvent.click(screen.getByLabelText(/Input schema/));
    await userEvent.paste(SCHEMA);
    await userEvent.type(screen.getByPlaceholderText("/repos/{owner}/{repo}/issues"), "/messages");

    // Both arguments into the JSON body, which is what a Messages API wants.
    const wheres = await screen.findAllByRole("combobox", { name: "" });
    for (const select of wheres.filter((s) =>
      Array.from(s.querySelectorAll("option")).some((o) => o.textContent === "JSON body"),
    )) {
      await userEvent.selectOptions(select, "body");
    }

    // The prompt is the caller's content and `audit` is append-only.
    await userEvent.click(screen.getByRole("checkbox", { name: "messages" }));

    await userEvent.click(screen.getByLabelText(/Token usage paths/));
    await userEvent.paste('{"input_tokens":"usage.input_tokens"}');

    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() =>
      expect(api.vetTool).toHaveBeenCalledWith(
        // The route's parameter, not the fixture's field — `connectorId` is what the
        // page was opened with and what the write is addressed to.
        "jira",
        "chat",
        expect.objectContaining({
          redact_args: ["messages"],
          binding: expect.objectContaining({
            method: "GET",
            path: "/messages",
            body: ["model", "messages"],
            query: [],
            usage_map: { input_tokens: "usage.input_tokens" },
          }),
        }),
      ),
    );
  });

  it("offers an OAuth app, which REST can carry and stdio cannot", async () => {
    // The bug 047 found by making a REST connector clickable at last. The gate read
    // `transport !== "http"`, so REST was told it could never have a consent flow and
    // the form was hidden — while `oauth.configure` refuses stdio and only stdio, and
    // `carries_per_user_credentials` has been true for REST since 045a. A screen
    // refusing what the server permits, silently removing a capability.
    show(rest());

    expect(await screen.findByText("Author a tool")).toBeInTheDocument();
    expect(screen.queryByText(/uses stdio/)).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Set up OAuth app" }),
    ).toBeInTheDocument();
  });

  it("says the tools are authored, not advertised, when none are approved yet", async () => {
    show(rest());

    expect(await screen.findByText(/Author each tool below/)).toBeInTheDocument();
    expect(screen.getByText(/A REST API does not describe its tools/)).toBeInTheDocument();
    expect(
      screen.queryByText(/Discover the server's tools below/),
    ).not.toBeInTheDocument();
  });

  it("says that re-authoring cannot carry the binding over", async () => {
    // `VettedTool` does not return `binding`, so a form that looked pre-filled would
    // silently replace a working request mapping with a blank — `ToolForm.start`'s trap
    // at a new address, where the missing half is bigger.
    show(
      connector({
        connector_id: "anthropic",
        transport: "rest",
        tools: [vetted({ name: "anthropic_chat", remote_name: "chat", effect: "write" })],
      }),
    );

    await userEvent.type(await screen.findByPlaceholderText("chat"), "chat");

    expect(await screen.findByText(/is already approved/)).toBeInTheDocument();
    expect(
      screen.getByText(/enter the method, path and schema again/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve again" })).toBeInTheDocument();
  });
});
