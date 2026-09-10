/** The question form, and the four things its answer must not overstate.
 *
 * Most of what can go wrong on this screen is a sentence that claims more than the server
 * checked, so these read the words. The verdict itself is the server's and is asserted
 * against the door in the backend suite; what is under test here is whether the page
 * reports it honestly.
 */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Simulate, { RULES } from "./Simulate";
import { api } from "../../lib/api";
import type { Simulation } from "../../lib/types";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return { ...actual, api: { simulateCall: vi.fn() } };
});

const NOT_CHECKED = [
  "authentication",
  "binding",
  "acting-for",
  "credential",
  "budget",
];

function answer(overrides: Partial<Simulation> = {}): Simulation {
  return {
    tool: "github_mcp_list_issues",
    verdict: "allowed",
    attributed_to: "triage",
    rule: "",
    reason: "",
    considered: [
      { agent: "security", allowed: false, rule: "outside_scope", reason: "outside secrets" },
      { agent: "triage", allowed: true, rule: "", reason: "" },
    ],
    not_checked: NOT_CHECKED,
    ...overrides,
  };
}

async function ask(tool = "github_mcp_list_issues", args: [string, string][] = []) {
  render(<Simulate tokenId="m_8f2c1a" />);
  fireEvent.change(screen.getByLabelText(/^Tool/), { target: { value: tool } });
  args.forEach(([name, value], index) => {
    fireEvent.change(screen.getByLabelText(`Argument ${index + 1} name`), {
      target: { value: name },
    });
    fireEvent.change(screen.getByLabelText(`Argument ${index + 1} value`), {
      target: { value },
    });
  });
  fireEvent.click(screen.getByRole("button", { name: "Check" }));
}

beforeEach(() => {
  vi.mocked(api.simulateCall).mockReset();
});

describe("asking", () => {
  it("sends the tool and only the named arguments", async () => {
    vi.mocked(api.simulateCall).mockResolvedValue(answer());

    await ask("github_mcp_list_issues", [["owner", "acme"]]);

    await waitFor(() =>
      expect(api.simulateCall).toHaveBeenCalledWith("m_8f2c1a", "github_mcp_list_issues", {
        owner: "acme",
      }),
    );
  });

  it("sends the tool name exactly as typed, spaces and all", async () => {
    // **Found in the edge pass.** It used to `.trim()`, which made this browser more
    // forgiving than the door: `tools/call` refuses ` post_message` outright, so
    // answering about `post_message` would be the screen correcting the question. One
    // character class of leniency is still a different verdict.
    vi.mocked(api.simulateCall).mockResolvedValue(answer());

    await ask(" post_message ", [["owner", "acme"]]);

    await waitFor(() =>
      expect(api.simulateCall).toHaveBeenCalledWith("m_8f2c1a", " post_message ", {
        owner: "acme",
      }),
    );
  });

  it("sends an argument value exactly as typed, because a resource may contain spaces", async () => {
    vi.mocked(api.simulateCall).mockResolvedValue(answer());

    await ask("t", [["  channel  ", " #eng "]]);

    await waitFor(() =>
      expect(api.simulateCall).toHaveBeenCalledWith("m_8f2c1a", "t", {
        // The *name* is trimmed — an empty box must not become an argument called `""` —
        // and the value is not.
        channel: " #eng ",
      }),
    );
  });

  it("drops a value with no name rather than inventing a key for it", async () => {
    vi.mocked(api.simulateCall).mockResolvedValue(answer());

    await ask("t", [["", "orphaned"]]);

    await waitFor(() => expect(api.simulateCall).toHaveBeenCalledWith("m_8f2c1a", "t", {}));
  });

  it("clears a previous verdict before asking again", async () => {
    // A stale verdict under a spinner is a wrong answer to the question being asked, and
    // it is the answer somebody screenshots.
    let release: (value: Simulation) => void = () => {};
    vi.mocked(api.simulateCall)
      .mockResolvedValueOnce(answer())
      .mockReturnValueOnce(new Promise((resolve) => (release = resolve)));

    await ask("t", [["owner", "acme"]]);
    expect(await screen.findByText("Would be allowed")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Check" }));

    await waitFor(() =>
      expect(screen.queryByText("Would be allowed")).not.toBeInTheDocument(),
    );
    release(answer({ verdict: "refused", rule: "outside_scope" }));
  });
});

describe("the answer", () => {
  it("lists every agent that was considered, with its own reason", async () => {
    // **The deliverable.** A verdict is what somebody could have got by making the call;
    // this list is what they could not.
    vi.mocked(api.simulateCall).mockResolvedValue(
      answer({
        verdict: "refused",
        rule: "outside_scope",
        reason: "github.repo 'other/x' is outside this agent's 'read' scope",
        considered: [
          { agent: "security", allowed: false, rule: "outside_scope", reason: "only secrets" },
          { agent: "triage", allowed: false, rule: "outside_scope", reason: "only acme" },
        ],
      }),
    );

    await ask("t", [["owner", "other"]]);

    expect(await screen.findByText("Would be denied")).toBeInTheDocument();
    expect(screen.getByText("only secrets")).toBeInTheDocument();
    expect(screen.getByText("only acme")).toBeInTheDocument();
  });

  it("does not print the deciding reason twice", async () => {
    // **Found by looking at the rendered page.** The top-level `reason` is the attributed
    // candidate's, so on any refusal with candidates it is already in the list below,
    // word for word — and printed twice it read as two separate findings.
    vi.mocked(api.simulateCall).mockResolvedValue(
      answer({
        verdict: "refused",
        rule: "outside_scope",
        reason: "only acme",
        considered: [
          { agent: "triage", allowed: false, rule: "outside_scope", reason: "only acme" },
        ],
      }),
    );

    await ask("t");

    await screen.findByText("Would be denied");
    expect(screen.getAllByText("only acme")).toHaveLength(1);
  });

  it("still prints the reason when there was nothing to list", async () => {
    // The tool-nobody-grants case: `considered` is empty, so the sentence has nowhere
    // else to appear and dropping it would leave a verdict with no reason at all.
    vi.mocked(api.simulateCall).mockResolvedValue(
      answer({
        verdict: "refused",
        attributed_to: null,
        rule: "not_granted",
        reason: "no agent this token is granted provides a tool called 'x'.",
        considered: [],
      }),
    );

    await ask("x");

    expect(
      await screen.findByText(/no agent this token is granted provides/),
    ).toBeInTheDocument();
  });

  it("says recorded under, not attributed to, when nothing allowed it", async () => {
    // Driving the CLI asked for these two words. *Attributed to* beside a refusal reads
    // as *this is the one that let it through*; what it names is the agent the denial
    // would be recorded against, which is a different and less reassuring fact.
    vi.mocked(api.simulateCall).mockResolvedValue(
      answer({ verdict: "refused", attributed_to: "security", rule: "outside_scope" }),
    );

    await ask("t");

    expect(await screen.findByText(/Recorded under security/)).toBeInTheDocument();
    expect(screen.queryByText(/Attributed to security/)).not.toBeInTheDocument();
  });

  it("says attributed to when one did allow it", async () => {
    vi.mocked(api.simulateCall).mockResolvedValue(answer());

    await ask("t");

    expect(await screen.findByText(/Attributed to triage/)).toBeInTheDocument();
  });

  it("always says what it did not check", async () => {
    // A verdict that implies more than it checked is worse than no verdict, and these
    // four are exactly what a reader would otherwise assume it covered.
    vi.mocked(api.simulateCall).mockResolvedValue(answer());

    await ask("t");

    expect(await screen.findByText("Not checked:")).toBeInTheDocument();
    expect(screen.getByText(/whether the token is active/)).toBeInTheDocument();
    expect(screen.getByText(/Nothing was called/)).toBeInTheDocument();
    expect(screen.getByText(/on-behalf-of claim could be verified/)).toBeInTheDocument();
    expect(screen.getByText(/No credential was read/)).toBeInTheDocument();
    expect(screen.getByText(/daily rate limit/)).toBeInTheDocument();
  });

  it("names the rule that decided, beside the verdict", async () => {
    // `rule` is the one field on the wire a reader can take to the server and grep for.
    // The first cut of this page rendered everything else and not it — the sentence
    // was there and the name of the branch that wrote it was not.
    vi.mocked(api.simulateCall).mockResolvedValue(
      answer({
        verdict: "refused",
        attributed_to: "triage",
        rule: "no_grant_for_effect",
        reason: "agent has no 'write' grant for github.repo",
        considered: [
          {
            agent: "triage",
            allowed: false,
            rule: "no_grant_for_effect",
            reason: "agent has no 'write' grant for github.repo",
          },
        ],
      }),
    );

    await ask("t");

    await screen.findByText("Would be denied");
    // Once beside the verdict and once beside the row it was attributed to.
    const labels = screen.getAllByText("no grant at this effect");
    expect(labels).toHaveLength(2);
    expect(labels[0]).toHaveAttribute("title", "rule: no_grant_for_effect");
  });

  it("names each considered agent's own rule, not the verdict's", async () => {
    vi.mocked(api.simulateCall).mockResolvedValue(
      answer({
        verdict: "refused",
        attributed_to: "security",
        rule: "outside_scope",
        reason: "only secrets",
        considered: [
          { agent: "security", allowed: false, rule: "outside_scope", reason: "only secrets" },
          {
            agent: "ops",
            allowed: false,
            rule: "resource_missing",
            reason: "'t' requires a permitted 'owner'",
          },
        ],
      }),
    );

    await ask("t");

    await screen.findByText("Would be denied");
    expect(screen.getByText("resource argument missing")).toBeInTheDocument();
    expect(screen.getAllByText("outside the scope")).toHaveLength(2);
  });

  it("names no rule on an allow, because an allow has none", async () => {
    vi.mocked(api.simulateCall).mockResolvedValue(answer());

    await ask("t");

    await screen.findByText("Would be allowed");
    // One rule label on the page, and it is the refusing candidate's — nothing beside
    // the verdict, and nothing beside `triage`, which allowed.
    const labels = screen.getAllByTitle(/^rule: /);
    expect(labels).toHaveLength(1);
    expect(labels[0]).toHaveTextContent("outside the scope");
    expect(labels[0].closest(".row")).toHaveTextContent("security");
  });

  it("renders an unknown rule as its raw name rather than hiding it", async () => {
    // The same argument as the not-checked key below: a tenth branch on the server
    // must be visible before it is explained. A lookup that dropped it would turn a
    // refusal into one with no reason given.
    vi.mocked(api.simulateCall).mockResolvedValue(
      answer({
        verdict: "refused",
        rule: "something_later",
        considered: [
          { agent: "triage", allowed: false, rule: "something_later", reason: "later" },
        ],
      }),
    );

    await ask("t");

    await screen.findByText("Would be denied");
    expect(screen.getAllByText("something_later")).toHaveLength(2);
  });

  it("renders an unknown not-checked key rather than hiding it", async () => {
    // A new thing this stops short of has to be visible before it is explained, never
    // after — a lookup that dropped what it did not recognise would silently narrow the
    // one list on this page whose job is to be complete.
    vi.mocked(api.simulateCall).mockResolvedValue(
      answer({ not_checked: [...NOT_CHECKED, "something_later"] }),
    );

    await ask("t");

    expect(await screen.findByText("something_later")).toBeInTheDocument();
  });

  it("says nothing about existence when no grant carries the tool", async () => {
    // The refusal must not become an existence oracle, and the page must not undo at the
    // last inch what the server was careful about.
    vi.mocked(api.simulateCall).mockResolvedValue(
      answer({
        verdict: "refused",
        attributed_to: null,
        rule: "not_granted",
        reason: "no agent this token is granted provides a tool called 'x'. Available: y.",
        considered: [],
      }),
    );

    await ask("x");

    expect(
      await screen.findByText(/No agent was checked/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Recorded under/)).not.toBeInTheDocument();
  });

  it("does not blame the grant when the name itself was the problem", async () => {
    // Both empty-`considered` refusals land in the same branch, and only one of them is
    // *nothing granted carries that tool*. The other is a name that could never have
    // been a tool name, whose cause is the sentence above — so this one states what
    // happened rather than why.
    vi.mocked(api.simulateCall).mockResolvedValue(
      answer({
        tool: " post_message ",
        verdict: "refused",
        attributed_to: null,
        rule: "not_granted",
        reason: "a tool name must match ^[a-zA-Z0-9_-]{1,64}$ — so ' post_message ' could not name one.",
        considered: [],
      }),
    );

    await ask(" post_message ");

    expect(await screen.findByText(/could not name one/)).toBeInTheDocument();
    expect(screen.getByText(/No agent was checked/)).toBeInTheDocument();
    expect(screen.queryByText(/carries that tool/)).not.toBeInTheDocument();
  });
});

describe("what it promises about itself", () => {
  it("says it changes nothing, on the form rather than in the answer", async () => {
    // In front of somebody deciding whether to press it — an assurance that only appears
    // after the act is an assurance nobody needed.
    render(<Simulate tokenId="m_8f2c1a" />);

    expect(
      screen.getByText(/Nothing is executed and no record is written/),
    ).toBeInTheDocument();
  });

  it("cannot be submitted without a tool", () => {
    render(<Simulate tokenId="m_8f2c1a" />);

    expect(screen.getByRole("button", { name: "Check" })).toBeDisabled();
  });
});

describe("the rule vocabulary", () => {
  it("labels exactly the nine names in core/permissions.RULES", () => {
    // The server closes its set with an AST walk over `permissions.check`
    // (`test_every_refusal_names_its_rule`); this closes the client's. A tenth rule
    // added there renders as its raw name until this list and `RULES` both learn of it —
    // and this is the test that says so, rather than a browser quietly printing a
    // snake_case identifier where a phrase belongs.
    const server = [
      "credential_smuggled",
      "not_described",
      "not_granted",
      "resource_missing",
      "composed_separator",
      "no_grant_for_effect",
      "outside_scope",
      "unsupported_reference",
      "headless_principal",
    ];

    expect(Object.keys(RULES).sort()).toEqual([...server].sort());
    for (const label of Object.values(RULES)) expect(label).not.toMatch(/_/);
  });
});
