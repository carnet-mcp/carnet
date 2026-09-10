/** *"This agent reaches Jira, and you have not connected your Jira account."*
 *
 * Step 7b's decision 8, second half. The failure it replaces is specific: before this,
 * somebody opened an agent, pressed Run, and got back either a third party's `401`
 * wrapped in a model's apology or — worse — a **successful** run made with the operator's
 * shared credential, reaching data that is not theirs and attributed to them in a log
 * kept forever. The second does not look like a problem at all, which is why it needs a
 * sentence before the button rather than an error after it.
 */

import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return { ...actual, api: { listConnections: vi.fn() } };
});

import ConnectionNotice from "./ConnectionNotice";
import { api } from "../../lib/api";
import type { AgentDetail, ConnectionSummary, ToolGroup } from "../../lib/types";

const AGENT: AgentDetail = {
  name: "triage-bot",
  runtime: "simple",
  tools: ["post_message", "jira_search_issues"],
  valid: true,
  error: null,
  system: "",
  scope: {},
  limits: {},
  updated_at: "2026-08-08T04:12:33.482391+00:00",
  your_role: "owner",
  version: 1,
  config: {},
};

/** A builtin group and a connector group, which is the shape `GET /tools` returns. */
const CATALOGUE: ToolGroup[] = [
  {
    origin: "builtin",
    id: "",
    description: "Tools that ship with the platform.",
    tools: [
      {
        name: "post_message",
        remote_name: null,
        description: "",
        note: "",
        effect: "write",
        resources: [],
        identity: "service" as const,
    max_response_bytes: null,
        vetted_by: "",
        vetted_at: "",
      },
    ],
  },
  {
    origin: "connector",
    id: "jira",
    description: "Acme's Jira",
    tools: [
      {
        name: "jira_search_issues",
        remote_name: "search_issues",
        description: "",
        note: "",
        effect: "read",
        identity: "service" as const,
        resources: [],
        max_response_bytes: null,
        vetted_by: "priya",
        vetted_at: "2026-08-01",
      },
    ],
  },
];

function connection(overrides: Partial<ConnectionSummary> = {}): ConnectionSummary {
  return {
    connector_id: "jira",
    description: "",
    state: "connectable",
    account_label: "",
    credential_kind: "",
    expires_at: null,
    // 035f put these on the wire. This component reads only `state`; they are here
    // because the fixture is the wire's shape and a partial one would type-check today
    // and hide the next field the same way.
    refresh_expires_at: null,
    updated_at: null,
    reconsent_reason: "",
    scopes: [],
    scope_notes: {},
    ...overrides,
  };
}

function show(connections: ConnectionSummary[], catalogue: ToolGroup[] | null = CATALOGUE) {
  vi.mocked(api.listConnections).mockResolvedValue(connections);
  return render(
    <MemoryRouter>
      <ConnectionNotice agent={AGENT} catalogue={catalogue} />
    </MemoryRouter>,
  );
}

beforeEach(() => vi.clearAllMocks());

describe("when it appears", () => {
  it("names the connector this agent needs and you have not connected", async () => {
    show([connection({ state: "connectable" })]);

    expect(
      await screen.findByText("This agent uses accounts you have not connected"),
    ).toBeTruthy();
    expect(screen.getByText("jira")).toBeTruthy();
  });

  it("says the honest thing about running anyway", async () => {
    // Not "it will fail" — it may quietly act as somebody else, which is the outcome
    // 7a's delegated credentials exist to prevent and the one a person cannot detect.
    show([connection({ state: "connectable" })]);

    expect(
      await screen.findByText(/denied or use a shared account set up by your administrator/),
    ).toBeTruthy();
  });

  it("leads somewhere", async () => {
    show([connection({ state: "connectable" })]);

    const link = await screen.findByRole("link", { name: "Connections" });
    expect(link.getAttribute("href")).toBe("/connections");
  });

  it("changes its heading when a connection has stopped working", async () => {
    // A different situation from never having connected: something that worked has
    // broken, and the person is likely mid-task rather than onboarding.
    show([
      connection({ state: "reconnect", reconsent_reason: "Consent was withdrawn." }),
    ]);

    expect(
      await screen.findByText("A connection needs attention"),
    ).toBeTruthy();
    expect(screen.getByText(/Consent was withdrawn/)).toBeTruthy();
  });
});

describe("when it stays out of the way", () => {
  it("says nothing when you are connected", async () => {
    const { container } = show([
      connection({ state: "connected", account_label: "priya@acme.com" }),
    ]);

    await waitFor(() => expect(api.listConnections).toHaveBeenCalled());
    expect(container.textContent).toBe("");
  });

  it("says nothing about a connector this agent does not use", async () => {
    // The join is the whole point. Warning about every unconnected connector in the
    // tenant would put a notice on every agent page and be ignored within a day.
    const { container } = show([connection({ connector_id: "linear" })]);

    await waitFor(() => expect(api.listConnections).toHaveBeenCalled());
    expect(container.textContent).toBe("");
  });

  it("says nothing when nobody can connect it anyway", async () => {
    // `unavailable` means no consent flow is configured. Telling somebody to connect
    // something they cannot connect is the dead-button failure in sentence form.
    const { container } = show([connection({ state: "unavailable" })]);

    await waitFor(() => expect(api.listConnections).toHaveBeenCalled());
    expect(container.textContent).toBe("");
  });

  it("says nothing when the catalogue has not loaded", async () => {
    const { container } = show([connection({ state: "connectable" })], null);

    await waitFor(() => expect(api.listConnections).toHaveBeenCalled());
    expect(container.textContent).toBe("");
  });

  it("stays silent when the connections request fails", async () => {
    // This is an advisory notice on somebody else's screen. A request the person did not
    // make must not put a red box on an agent page.
    vi.mocked(api.listConnections).mockRejectedValue(new Error("network"));
    const { container } = render(
      <MemoryRouter>
        <ConnectionNotice agent={AGENT} catalogue={CATALOGUE} />
      </MemoryRouter>,
    );

    await waitFor(() => expect(api.listConnections).toHaveBeenCalled());
    expect(container.textContent).toBe("");
  });
});
