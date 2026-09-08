/** The list, and the decisions its 83 lines carry.
 *
 * Named as untested by `DEFERRED.md`'s section-F row through two agings-out; this file
 * is that row coming due. What is worth pinning is not the table — it is:
 *
 *   - **an empty list is an answer, not a fault.** Absence is denial, this is a first
 *     day's screen, and one word of breakage turns design into a support ticket.
 *   - **a broken agent is listed with its reason** rather than hidden — the server
 *     validates rows itself so that an agent that vanishes when it breaks is not one
 *     somebody re-creates.
 *   - **"New MCP" is outside the loading and error branches.** The person whose list
 *     failed is the person most likely to want it.
 *   - the standing four: happy path, empty, the 403 verbatim, one fetch and no poll.
 */

import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return { ...actual, api: { listAgents: vi.fn() } };
});

import AgentsPage, { appsOf, describe as describeAgent, status } from "./AgentsPage";
import { api, ApiError } from "../../lib/api";
import type { AgentSummary } from "../../lib/types";

function agent(overrides: Partial<AgentSummary> = {}): AgentSummary {
  return {
    name: "triage",
    runtime: "simple",
    tools: ["list_issues", "post_message"],
    valid: true,
    error: null,
    ...overrides,
  };
}

function show(rows: AgentSummary[]) {
  vi.mocked(api.listAgents).mockResolvedValue(rows);
  return render(
    <MemoryRouter>
      <AgentsPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(api.listAgents).mockReset();
});

describe("the list", () => {
  it("renders each agent as a card linking to it, with its tool count", async () => {
    show([agent(), agent({ name: "rota", tools: ["read_calendar"] })]);

    const row = (await screen.findByText("triage")).closest("a");
    expect(row).toHaveAttribute("href", "/agents/triage");
    expect(row).toHaveClass("conn-card");
    // The count is in the sentence and nowhere else — said once, not once in a header
    // and again underneath it.
    expect(screen.getByText("2 tools, all built in.")).toBeInTheDocument();
    expect(screen.getByText("1 tool, all built in.")).toBeInTheDocument();
  });

  it("lists a broken agent with the validator's reason, not hidden", async () => {
    show([agent({ valid: false, error: "scope names a tool it is not granted" })]);

    expect(await screen.findByText("Not valid")).toBeInTheDocument();
    expect(
      screen.getByText("scope names a tool it is not granted"),
    ).toBeInTheDocument();
  });

  it("states an empty list as what the account can reach, with no word of breakage", async () => {
    show([]);

    expect(await screen.findByText("No agents here yet")).toBeInTheDocument();
    expect(screen.queryByText(/error|failed/i)).not.toBeInTheDocument();
  });

  it("offers both exits from the empty state, and both are true (062)", async () => {
    // The sharing road is the ordinary case in an established workspace; the create
    // road is the ONLY road for a fresh deployment's first administrator, who used
    // to be told to ask a person who does not exist.
    show([]);

    await screen.findByText("No agents here yet");
    expect(screen.getByText(/Ask whoever owns the agent you need/)).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /Create your first MCP/ }),
    ).toHaveAttribute("href", "/agents/new");
  });
});

describe("the standing pair", () => {
  it("renders the server's 403 verbatim", async () => {
    vi.mocked(api.listAgents).mockRejectedValue(
      new ApiError(403, "your domain is not registered with this service"),
    );
    render(
      <MemoryRouter>
        <AgentsPage />
      </MemoryRouter>,
    );

    expect(
      await screen.findByText("your domain is not registered with this service"),
    ).toBeInTheDocument();
    // The decision the docstring argues: creation does not depend on the request
    // having succeeded, so the action survives the error branch.
    expect(screen.getByRole("link", { name: /New MCP/ })).toBeInTheDocument();
  });

  it("asks once and does not poll", async () => {
    show([agent()]);
    await screen.findByText("triage");

    expect(api.listAgents).toHaveBeenCalledTimes(1);
  });
});


// --- 092: the card, and the apps it names --------------------------------------------

describe("which apps an agent touches", () => {
  it("reads them off the connector prefix the tool names already carry", () => {
    // No second request: `<connector>_<tool>` is what makes a local name unambiguous,
    // so the list already holds the answer.
    expect(appsOf(["github_list_issues", "jira_create_issue"]).map((a) => a.label)).toEqual([
      "GitHub",
      "Jira",
    ]);
  });

  it("says each app once, however many of its tools are granted", () => {
    expect(
      appsOf(["github_list_issues", "github_create_pr", "github_read_file"]),
    ).toHaveLength(1);
  });

  it("names nothing for a built-in, rather than inventing an app called post", () => {
    // 091's rule one screen over: a wrong mark is worse than no mark. `post_message`
    // has no connector in front of it, and a monogram tile reading "P" would be a logo
    // for a vendor that does not exist.
    expect(appsOf(["post_message", "read_calendar"])).toEqual([]);
  });

  it("keeps the recognised ones when a built-in is mixed in", () => {
    expect(appsOf(["post_message", "notion_search"]).map((a) => a.label)).toEqual([
      "Notion",
    ]);
  });
});

describe("the badge and the sentence", () => {
  // `ConnectorsPage`'s pair, on this screen for the same reason: a badge is read by
  // somebody scanning nine cards and a sentence by the one who stops. They must agree.
  it("agrees with describe() on every branch", () => {
    const broken = agent({ valid: false, error: "scope names a tool it is not granted" });
    expect(status(broken).word).toBe("Not valid");
    expect(describeAgent(broken)).toBe("scope names a tool it is not granted");

    const bare = agent({ tools: [] });
    expect(status(bare).word).toBe("No tools");
    expect(describeAgent(bare)).toContain("touch nothing");

    const ready = agent({ tools: ["github_list_issues"] });
    expect(status(ready).word).toBe("Ready");
    expect(describeAgent(ready)).toBe("1 tool, across GitHub.");
  });

  it("names the apps in words, so the marks are never the only carrier", async () => {
    // Every tile is `aria-hidden` — decoration beside a sentence, exactly as on the
    // connectors tab. A card whose only statement of what it touches was a logo would
    // say nothing at all to a screen reader.
    show([agent({ name: "triage", tools: ["github_list_issues", "jira_create_issue"] })]);

    const card = (await screen.findByText("triage")).closest("a") as HTMLElement;
    expect(card).toHaveTextContent("2 tools, across GitHub and Jira.");
    card.querySelectorAll(".brandmark").forEach((mark) => {
      expect(mark).toHaveAttribute("aria-hidden", "true");
    });
  });

  it("says all built in rather than across nothing", () => {
    // The branch a naive join produces as "3 tools, across ." — reachable on any
    // deployment whose agents use only the platform's own tools.
    expect(describeAgent(agent({ tools: ["post_message", "read_calendar"] }))).toBe(
      "2 tools, all built in.",
    );
  });

  it("falls back to a sentence when a broken agent carries no reason", () => {
    expect(describeAgent(agent({ valid: false, error: null }))).toContain(
      "no longer validates",
    );
  });
});
