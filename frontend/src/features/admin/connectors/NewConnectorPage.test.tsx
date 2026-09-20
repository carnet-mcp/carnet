/** The connector setup as a sequence (107 D4), and the four things it must not get wrong.
 *
 *   - **the host gate is the address step's, with the way through beside it.** Nothing is
 *     registered before the host is approved, and the approval is offered where the
 *     question is asked rather than on another card.
 *   - **what the form collects is what goes on the wire**, field for field — the
 *     registration tests moved here from the list page unchanged in what they assert.
 *   - **a preset fills the steps and decides nothing**: every value is editable, the id is
 *     sent as provenance for the server to apply, and a hand-filled setup sends none.
 *   - **the OAuth app is pre-filled from the preset and set up in the same act**, client
 *     id and secret excepted — the step the owner found blank.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../../lib/api")>("../../../lib/api");
  return {
    ...actual,
    api: {
      listHosts: vi.fn(),
      approveHost: vi.fn(),
      listRecipes: vi.fn(),
      registerConnector: vi.fn(),
      configureOAuth: vi.fn(),
      getConnector: vi.fn(),
      discover: vi.fn(),
      discoveryCredential: vi.fn(),
      vetTool: vi.fn(),
      startConnect: vi.fn(),
    },
  };
});

import NewConnectorPage, { hostOf } from "./NewConnectorPage";
import { api, ApiError } from "../../../lib/api";
import type { ConnectorDetail, HostEntry, Recipe } from "../../../lib/types";

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

function connector(overrides: Partial<ConnectorDetail> = {}): ConnectorDetail {
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
    tools: [],
    ...overrides,
  };
}

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

function show(hosts: HostEntry[] = [host()], recipes: Recipe[] = [], path = "/admin/connectors/new") {
  vi.mocked(api.listHosts).mockResolvedValue(hosts);
  vi.mocked(api.listRecipes).mockResolvedValue(recipes);
  vi.mocked(api.getConnector).mockResolvedValue(connector());
  vi.mocked(api.discoveryCredential).mockResolvedValue({ credential: "none", shared_via: "" });
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/admin/connectors/new" element={<NewConnectorPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

const next = () => screen.getByRole("button", { name: "Continue" });

/** Through the first three steps by hand, to the credentials step. */
async function toCredentials(id = "jira", url = "https://mcp.acme.com/mcp", kind: "http" | "rest" = "http") {
  await screen.findByRole("heading", { name: "Start" });
  await userEvent.click(next());
  await userEvent.type(screen.getByPlaceholderText("https://mcp.acme.com/mcp"), url);
  await waitFor(() => expect(next()).toBeEnabled());
  await userEvent.click(next());
  await userEvent.type(screen.getByPlaceholderText("jira"), id);
  if (kind === "rest") await userEvent.click(screen.getByRole("radio", { name: /REST API/ }));
  await userEvent.click(next());
  await screen.findByRole("button", { name: "Register" });
}

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn === "function" && "mockReset" in fn) vi.mocked(fn).mockReset();
  }
});

describe("the host gate, on the address step", () => {
  it("will not continue past an unapproved host, and offers to approve it there", async () => {
    vi.mocked(api.approveHost).mockResolvedValue({ host: "mcp.acme.com", note: "", warning: "" });
    show([]);

    await screen.findByRole("heading", { name: "Start" });
    await userEvent.click(next());
    await userEvent.type(screen.getByPlaceholderText("https://mcp.acme.com/mcp"), "https://mcp.acme.com/mcp");

    expect(await screen.findByText("not approved")).toBeInTheDocument();
    expect(next()).toBeDisabled();
    expect(screen.getByText(/Approve mcp.acme.com to continue/)).toBeInTheDocument();

    vi.mocked(api.listHosts).mockResolvedValue([host()]);
    await userEvent.click(screen.getByRole("button", { name: "Approve host" }));

    await waitFor(() => expect(api.approveHost).toHaveBeenCalledWith("mcp.acme.com", ""));
    expect(await screen.findByText("approved")).toBeInTheDocument();
    await waitFor(() => expect(next()).toBeEnabled());
  });

  it("does not count a host that can never be dialled as an approved one", async () => {
    show([host({ host: "localhost", warning: "Recorded, but 'localhost' will NOT be dialled" })]);

    await screen.findByRole("heading", { name: "Start" });
    await userEvent.click(next());
    await userEvent.type(screen.getByPlaceholderText("https://mcp.acme.com/mcp"), "http://localhost/mcp");

    expect(await screen.findByText("not approved")).toBeInTheDocument();
    expect(next()).toBeDisabled();
  });

  it("names the host as the allowlist spells it", () => {
    expect(hostOf("https://MCP.Acme.com:443/mcp")).toBe("mcp.acme.com");
    expect(hostOf("not a url")).toBe("");
  });
});

describe("registering", () => {
  it("sends what the steps collected, then lands on the tools step", async () => {
    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    show();
    await toCredentials();

    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() =>
      expect(api.registerConnector).toHaveBeenCalledWith({
        connector_id: "jira",
        url: "https://mcp.acme.com/mcp",
        kind: "http",
        credential_env: "",
        credential_ref: "",
        description: "",
        allow_asserted_identity: false,
      }),
    );
    expect(api.configureOAuth).not.toHaveBeenCalled();
    expect(await screen.findByText("Available tools")).toBeInTheDocument();
  });

  it("sends a REST connector's own credential scheme, and only for REST", async () => {
    vi.mocked(api.registerConnector).mockResolvedValue(connector({ transport: "rest" }));
    show();
    await toCredentials("anthropic", "https://mcp.acme.com/v1", "rest");

    await userEvent.type(screen.getByLabelText(/Credential variable/), "ANTHROPIC_KEY");
    await userEvent.click(screen.getByText("How the credential is sent"));
    await userEvent.type(screen.getByLabelText(/Credential header/), "x-api-key");
    await userEvent.clear(screen.getByLabelText(/Credential prefix/));
    await userEvent.click(screen.getByRole("button", { name: "Add a header" }));
    await userEvent.type(screen.getByPlaceholderText("anthropic-version"), "anthropic-version");
    await userEvent.type(screen.getByPlaceholderText("2023-06-01"), "2023-06-01");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() =>
      expect(api.registerConnector).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "rest",
          credential_env: "ANTHROPIC_KEY",
          credential_header: "x-api-key",
          credential_prefix: "",
          headers: { "anthropic-version": "2023-06-01" },
        }),
      ),
    );
  });

  it("offers the REST credential fields to nobody else", async () => {
    show();
    await toCredentials();

    expect(screen.queryByText("How the credential is sent")).not.toBeInTheDocument();
  });

  it("sends a vault reference in place of the variable, and the other one empty", async () => {
    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    show();
    await toCredentials();

    await userEvent.click(screen.getByRole("radio", { name: /Vault reference/ }));
    await userEvent.type(screen.getByPlaceholderText("op://Engineering/Jira/credential"), "op://Eng/Jira/credential");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() =>
      expect(api.registerConnector).toHaveBeenCalledWith(
        expect.objectContaining({ credential_env: "", credential_ref: "op://Eng/Jira/credential" }),
      ),
    );
  });

  it("sets asserted identity at registration when it is ticked, and says what it means", async () => {
    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    show();
    await toCredentials();

    expect(screen.getByText(/without verification/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() =>
      expect(api.registerConnector).toHaveBeenCalledWith(
        expect.objectContaining({ allow_asserted_identity: true }),
      ),
    );
  });

  it("renders the server's refusal verbatim and stays on the step", async () => {
    vi.mocked(api.registerConnector).mockRejectedValue(
      new ApiError(400, "connector 'jira' already exists in this tenant."),
    );
    show();
    await toCredentials();

    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    expect(await screen.findByText(/already exists in this tenant/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Register" })).toBeInTheDocument();
  });
});

describe("a preset", () => {
  it("fills the steps, stays editable, and is sent for the server to apply", async () => {
    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    show([host()], [recipe()]);

    await userEvent.click(await screen.findByRole("radio", { name: /Jira/ }));
    expect(screen.getByText(/have not been verified/)).toBeInTheDocument();
    await userEvent.click(next());

    // The address, from the preset — and its host, approved.
    expect(screen.getByDisplayValue("https://mcp.acme.com/mcp")).toBeInTheDocument();
    expect(await screen.findByText("approved")).toBeInTheDocument();
    const url = screen.getByDisplayValue("https://mcp.acme.com/mcp");
    await userEvent.clear(url);
    await userEvent.type(url, "https://mcp.acme.com/v2/mcp");
    await userEvent.click(next());

    expect(screen.getByDisplayValue("jira")).toBeInTheDocument();
    await userEvent.click(next());

    expect(await screen.findByDisplayValue("JIRA_TOKEN")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() =>
      expect(api.registerConnector).toHaveBeenCalledWith(
        expect.objectContaining({
          connector_id: "jira",
          url: "https://mcp.acme.com/v2/mcp",
          credential_env: "JIRA_TOKEN",
          from_recipe: "atlassian-jira",
        }),
      ),
    );
  });

  it("sends no recipe when the setup was filled by hand", async () => {
    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    show([host()], [recipe()]);
    await screen.findByText("Jira");
    await toCredentials("mine", "https://mcp.acme.com/x");

    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() => expect(api.registerConnector).toHaveBeenCalled());
    expect(api.registerConnector).toHaveBeenCalledWith(
      expect.not.objectContaining({ from_recipe: expect.anything() }),
    );
  });

  it("pre-fills the OAuth app from the preset and sets it up in the same act, secret and all", async () => {
    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    vi.mocked(api.configureOAuth).mockResolvedValue({
      app: {
        connector_id: "jira",
        authorize_endpoint: "https://auth.atlassian.com/authorize",
        token_endpoint: "https://auth.atlassian.com/oauth/token",
        revoke_endpoint: "",
        client_id: "client-abc",
        scopes: ["read:jira-work"],
        scope_notes: {},
        authorize_params: {},
        configured_by: "user:u_9311",
        configured_at: "2026-09-15T00:00:00+00:00",
      },
      redirect_uri: "https://x/connect/callback",
      warnings: [],
    });
    show([host()], [recipe()]);

    await userEvent.click(await screen.findByRole("radio", { name: /Jira/ }));
    await userEvent.click(next());
    await screen.findByText("approved");
    await userEvent.click(next());
    await userEvent.click(next());

    expect(await screen.findByText("From the Jira preset")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("https://auth.acme.com/authorize")).toHaveValue(
      "https://auth.atlassian.com/authorize",
    );
    expect(screen.getByLabelText(/^Client ID/)).toHaveValue("");
    await userEvent.type(screen.getByLabelText(/^Client ID/), "client-abc");
    await userEvent.type(screen.getByLabelText(/^Client secret/), "s3cret");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() =>
      expect(api.configureOAuth).toHaveBeenCalledWith(
        "jira",
        expect.objectContaining({
          authorize_endpoint: "https://auth.atlassian.com/authorize",
          token_endpoint: "https://auth.atlassian.com/oauth/token",
          client_id: "client-abc",
          client_secret: "s3cret",
          scopes: ["read:jira-work"],
        }),
      ),
    );
    expect(await screen.findByText("Available tools")).toBeInTheDocument();
  });

  it("keeps the registration and says so when the OAuth app is refused", async () => {
    vi.mocked(api.registerConnector).mockResolvedValue(connector());
    vi.mocked(api.configureOAuth).mockRejectedValue(
      new ApiError(400, "the token endpoint's host is not an approved host."),
    );
    show([host()], [recipe()]);

    await userEvent.click(await screen.findByRole("radio", { name: /Jira/ }));
    await userEvent.click(next());
    await screen.findByText("approved");
    await userEvent.click(next());
    await userEvent.click(next());
    await userEvent.type(await screen.findByLabelText(/^Client ID/), "client-abc");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    expect(await screen.findByText("Registered, and the OAuth app was not set up")).toBeInTheDocument();
    expect(screen.getByText(/not an approved host/)).toBeInTheDocument();
  });
});

describe("coming back", () => {
  it("lands on the tools step for a connector the setup already registered", async () => {
    show([host()], [], "/admin/connectors/new?connector=jira");

    expect(await screen.findByText("Available tools")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Done" })).toBeInTheDocument();
  });
});
