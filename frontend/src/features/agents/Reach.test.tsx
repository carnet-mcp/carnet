/** The one description of the permission model, tested where all three screens borrow it.
 *
 * Three parents render this — the agent detail page, the wizard's review step, the token
 * detail page — and none of their tests assert its internals, which made a 307-line
 * component with the app's most important sentences effectively untested. The sentences
 * are the point:
 *
 *   - **writes are grouped and stated first**, with the singular spelled correctly —
 *     "One tool that alter a system" was this repository's canonical frontend bug, on
 *     the most important line of the permissions screen.
 *   - **a granted tool the catalogue no longer describes is a warning, not a crash** —
 *     a connector was withdrawn underneath a live agent.
 *   - **a missing catalogue degrades by saying which half is missing**, because a screen
 *     that silently dropped the read/write annotation would read as "none of these
 *     write".
 *   - **the scope table pairs each entry with the tools that use it**, and an entry
 *     nothing uses says so rather than rendering an empty cell.
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import Reach, { resolve } from "./Reach";
import { ApiError } from "../../lib/api";
import type { ToolGroup, ToolSummary } from "../../lib/types";

function tool(overrides: Partial<ToolSummary> = {}): ToolSummary {
  return {
    name: "list_issues",
    remote_name: "issues/list",
    description: "Read the issues in a repository.",
    note: "",
    effect: "read",
    identity: "service",
    resources: [{ type: "github.repo" }],
    max_response_bytes: null,
    vetted_by: "user:u_admin",
    vetted_at: "2026-08-01T09:00:00+00:00",
    ...overrides,
  };
}

const CATALOGUE: ToolGroup[] = [
  {
    origin: "connector",
    id: "acme",
    description: "",
    tools: [
      tool(),
      tool({
        name: "post_message",
        effect: "write",
        resources: [{ type: "chat.channel" }],
        description: "",
      }),
    ],
  },
];

function show(
  agent: { tools: string[]; scope: Record<string, Record<string, string[]>> },
  catalogue: ToolGroup[] | null = CATALOGUE,
  failed: unknown = null,
) {
  return render(<Reach agent={agent} catalogue={catalogue} failed={failed} />);
}

describe("the sentences", () => {
  it("states no tools at all as a capability, in one sentence", () => {
    show({ tools: [], scope: {} });

    expect(screen.getByText("This agent has no tools.")).toBeInTheDocument();
  });

  it("puts the write first and conjugates the singular", () => {
    // The canonical bug, pinned: "One tool that can change" — singular, not plural.
    show({ tools: ["post_message", "list_issues"], scope: {} });

    expect(screen.getByText("Write tools")).toBeInTheDocument();
    expect(
      screen.getByText("One tool that can change data in the connected system."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("One tool that reads data and changes nothing."),
    ).toBeInTheDocument();
  });

  it("says where a tool came from, and that an undescribed one has no description", () => {
    show({ tools: ["post_message"], scope: {} });

    expect(screen.getByText("from acme")).toBeInTheDocument();
    expect(screen.getByText("No description.")).toBeInTheDocument();
  });

  it("warns about a granted tool the catalogue no longer describes", () => {
    show({ tools: ["list_issues", "withdrawn_tool"], scope: {} });

    expect(screen.getByText("Granted, and no longer available")).toBeInTheDocument();
    expect(screen.getByText(/withdrawn_tool is/)).toBeInTheDocument();
  });
});

describe("without a catalogue", () => {
  it("still names the tools, and says which half is missing while loading", () => {
    show({ tools: ["list_issues"], scope: {} }, null);

    expect(screen.getByText("list_issues")).toBeInTheDocument();
    expect(screen.getByText(/Loading tool details/)).toBeInTheDocument();
  });

  it("renders the catalogue's failure beside the names when it could not load", () => {
    show(
      { tools: ["list_issues"], scope: {} },
      null,
      new ApiError(503, "the database is not reachable"),
    );

    expect(
      screen.getByText(/could not be loaded. Tool effects are not shown/),
    ).toBeInTheDocument();
    expect(screen.getByText("the database is not reachable")).toBeInTheDocument();
  });
});

describe("the scope table", () => {
  it("says no selected resources means any resource the caller can reach", () => {
    // `list_issues` declares `github.repo`, so the open-access sentence is the true one.
    show({ tools: ["list_issues"], scope: {} });

    expect(
      screen.getByText(/No resources are selected.*any resource the caller's account can reach/),
    ).toBeInTheDocument();
  });

  it("says the tools take no resource when none of the granted ones declares one", () => {
    show(
      { tools: ["list_issues"], scope: {} },
      [{ ...CATALOGUE[0], tools: [tool({ resources: [] })] }],
    );

    expect(
      screen.getByText(/do not take a resource, so they are not restricted/),
    ).toBeInTheDocument();
  });

  it("assumes open access when the catalogue is unknown", () => {
    // Without the catalogue the tools' resources cannot be read, so the sentence that
    // says access is open is the safe one.
    show({ tools: ["list_issues"], scope: {} }, null);

    expect(screen.getByText(/No resources are selected/)).toBeInTheDocument();
  });

  it("pairs each entry with the granted tools that touch it", () => {
    show({
      tools: ["list_issues"],
      scope: { "github.repo": { read: ["acme/site", "acme/api"] } },
    });

    // Scoped to the table: the ToolRow's resource Tag says "github.repo" too.
    const row = within(screen.getByRole("table")).getByText("github.repo").closest("tr");
    expect(row).not.toBeNull();
    // Two patterns, one cell; the matcher sees whitespace-normalized text.
    expect(within(row as HTMLElement).getByText("acme/site acme/api")).toBeInTheDocument();
    expect(within(row as HTMLElement).getByText("list_issues")).toBeInTheDocument();
  });

  it("says so when nothing granted uses a scope entry, rather than leaving a blank", () => {
    show({
      tools: ["list_issues"],
      scope: { "chat.channel": { write: ["#ops"] } },
    });

    expect(screen.getByText("no granted tool uses this")).toBeInTheDocument();
  });
});

describe("resolve", () => {
  it("keeps a name the catalogue does not know, marked as unknown", () => {
    const granted = resolve(["list_issues", "gone"], CATALOGUE);

    expect(granted).toHaveLength(2);
    expect(granted[0].origin).toBe("acme");
    expect(granted[1]).toEqual({ name: "gone", tool: null, origin: "" });
  });
});
