/** The transpose, and the two claims it must not make.
 *
 * The component is a rendering of a server answer, so most of what could go wrong here is
 * a wrong *sentence* rather than a wrong number — which is why these read the words as
 * well as the values. The two that matter: it must not imply which agent takes a call,
 * and it must not drop a row it cannot describe.
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import EffectiveReach from "./EffectiveReach";
import type { ToolReach } from "../../lib/types";

const SHARED: ToolReach = {
  tool: "github_mcp_list_issues",
  effect: "read",
  resource_types: ["github.repo"],
  granted_by: [
    { agent: "security-triage", applies: { "github.repo": ["acme/secrets-*"] } },
    { agent: "triage", applies: { "github.repo": ["acme/*"] } },
  ],
};

const WRITE: ToolReach = {
  tool: "github_mcp_create_issue",
  effect: "write",
  resource_types: ["github.repo"],
  granted_by: [{ agent: "filer", applies: { "github.repo": ["acme/*"] } }],
};

describe("the transpose", () => {
  it("puts every agent that grants one tool under that tool", () => {
    render(<EffectiveReach rows={[SHARED]} />);

    const row = screen
      .getByText("github_mcp_list_issues")
      .closest(".row") as HTMLElement;
    expect(within(row).getByText("security-triage")).toBeInTheDocument();
    expect(within(row).getByText("triage")).toBeInTheDocument();
    expect(within(row).getByText("acme/secrets-*")).toBeInTheDocument();
    expect(within(row).getByText("acme/*")).toBeInTheDocument();
  });

  it("never names the agent a call would be attributed to", () => {
    // **The defect the first build shipped.** `attributed_to` named `granted_by[0]`,
    // which is wrong in exactly this case: the union rule is *first allow wins*, so a
    // call about `acme/web` goes to `triage` while the field claimed `security-triage`.
    // The order is true; the winner is not knowable without the arguments.
    render(<EffectiveReach rows={[SHARED]} />);

    expect(screen.queryByText(/attributed to security-triage/i)).not.toBeInTheDocument();
    expect(
      screen.getByText(/decided per call, so this page cannot say in advance/),
    ).toBeInTheDocument();
  });

  it("says the order is the attribution order, since that much is true", () => {
    render(<EffectiveReach rows={[SHARED]} />);

    expect(
      screen.getByText(/attributed to the first of them whose scope admits/),
    ).toBeInTheDocument();
  });

  it("states writes before reads", () => {
    // `Reach.tsx`'s rule, kept, because the two sit on one page and a reader should not
    // have to learn two orderings. *What can this change* is the question; burying a
    // write among reads answers it only for somebody who reads all of them.
    render(<EffectiveReach rows={[SHARED, WRITE]} />);

    const names = screen
      .getAllByText(/^github_mcp_/)
      .map((node) => node.textContent);
    expect(names).toEqual(["github_mcp_create_issue", "github_mcp_list_issues"]);
  });

  it("shows a granted tool nothing describes rather than dropping it", () => {
    // Dropping the row makes the token look narrower than it is, which is the wrong
    // direction to be wrong in.
    render(
      <EffectiveReach
        rows={[
          {
            tool: "vanished_tool",
            effect: null,
            resource_types: [],
            granted_by: [{ agent: "stale", applies: {} }],
          },
        ]}
      />,
    );

    expect(screen.getByText("vanished_tool")).toBeInTheDocument();
    expect(screen.getByText("not described")).toBeInTheDocument();
    expect(screen.getByText(/every call to it is refused/)).toBeInTheDocument();
  });

  it("calls out an agent that carries a tool and grants nothing at its effect", () => {
    // A refusal waiting to happen, and worth reading as one rather than as an empty cell.
    render(
      <EffectiveReach
        rows={[
          {
            tool: "github_mcp_list_issues",
            effect: "read",
            resource_types: ["github.repo"],
            granted_by: [{ agent: "narrow", applies: { "github.repo": [] } }],
          },
        ]}
      />,
    );

    expect(screen.getByText("no grant at this effect")).toBeInTheDocument();
  });

  it("renders nothing at all when the token is granted nothing", () => {
    // The card above already says so in a sentence. A second, emptier way of saying it
    // reads as a thing that failed to load.
    const { container } = render(<EffectiveReach rows={[]} />);

    expect(container).toBeEmptyDOMElement();
  });

  it("says nothing about more than one agent when there is only one", () => {
    render(<EffectiveReach rows={[WRITE]} />);

    expect(screen.queryByText(/granted by more than one agent/)).not.toBeInTheDocument();
  });
});
