/** The form, driven the way somebody uses it.
 *
 * `draft.test.ts` proves the derivation is correct for every combination of tools. This
 * proves the *interface over it* — that ticking a tool asks the right question, that
 * unticking stops asking it, that nothing here shows anybody a pattern, and that the
 * review step and the agent's own page are the same screen.
 *
 * The last one is a **diff**, not two similar assertions. Decision 8 is that the review
 * step and the detail page are one component, and the whole value of that is that they
 * cannot disagree — which is a property no amount of "and it also says X" establishes.
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../../lib/api")>(
    "../../../lib/api",
  );
  return {
    ...actual,
    api: {
      listTools: vi.fn(),
      createAgent: vi.fn(),
      validateDraft: vi.fn(),
      getAgent: vi.fn(),
      // The detail page renders the share sheet as of 10d, and the last test below
      // renders that page to diff it against the review step.
      agentAccess: vi.fn(),
      listGroups: vi.fn(),
      // ...and `ConnectionNotice` as of 7b, for the same reason.
      listConnections: vi.fn(),
      // The last test renders the detail page, which carries the history card as of 021.
      agentVersions: vi.fn(),
      myTokens: vi.fn(),
      // ...and the connect card as of 044, which asks whether anything has knocked.
      doorActivity: vi.fn(),
      deleteAgent: vi.fn(),
      shareAgent: vi.fn(),
      unshareAgent: vi.fn(),
    },
  };
});

import CreateAgentPage from "./CreateAgentPage";
import AgentDetailPage from "../AgentDetailPage";
import { api, ApiError } from "../../../lib/api";
import { MeContext } from "../../../lib/me";
import type { AgentDetail, ToolGroup } from "../../../lib/types";

const POST_MESSAGE = {
  name: "post_message",
  remote_name: null,
  description: "Post a message to a team chat channel.",
  note: "",
  effect: "write" as const,
  resources: [{ type: "chat.channel" }],
  identity: "service" as const,
  max_response_bytes: null,
  vetted_by: "",
  vetted_at: "",
};

const LIST_ISSUES = {
  ...POST_MESSAGE,
  name: "github_mcp_list_issues",
  remote_name: "list_issues",
  description: "List issues in a GitHub repository.",
  note: "Scope it to the repositories a team actually owns.",
  effect: "read" as const,
  resources: [{ type: "github.repo" }],
  max_response_bytes: 262144,
};

// Step 045a: a tool vetted on a REST connector arrives through the identical wire
// shape — origin "connector", grouped by connector id — which is the whole argument
// that the wizard needs no change for the second connector kind. Its description is
// the vetter's words (there is no server to copy from) and its provenance is empty,
// which is that row's honest stored state rather than a gap in the fixture.
const TRACKER_LIST = {
  ...POST_MESSAGE,
  name: "tracker_list_issues",
  remote_name: "list_issues",
  description: "List issues in a repository.",
  note: "Authored at vetting time.",
  effect: "read" as const,
  resources: [{ type: "github.repo" }],
};

const CATALOGUE: ToolGroup[] = [
  { origin: "builtin", id: "", description: "", tools: [POST_MESSAGE] },
  { origin: "connector", id: "github-mcp", description: "", tools: [LIST_ISSUES] },
  {
    origin: "connector",
    id: "tracker",
    description: "Acme's issue tracker, plain REST.",
    tools: [TRACKER_LIST],
  },
];

/** The shell's `/me`, supplied because the pages read it through context. */
function withMe(children: React.ReactNode) {
  return (
    <MeContext.Provider
      value={{
        me: {
          principal: "user:u_9311",
          kind: "user",
          email: "priya@acme.com",
          display_name: "Priya",
          admin: false,
        },
        settled: true,
      }}
    >
      {children}
    </MeContext.Provider>
  );
}

function open(catalogue: ToolGroup[] = CATALOGUE) {
  vi.mocked(api.listTools).mockResolvedValue(catalogue);
  vi.mocked(api.validateDraft).mockResolvedValue({ valid: true });
  vi.mocked(api.myTokens).mockResolvedValue([]);
  vi.mocked(api.doorActivity).mockResolvedValue({ calls: 0, last_call_at: null });
  return render(
    withMe(
      <MemoryRouter initialEntries={["/agents/new"]}>
        <Routes>
          <Route path="/agents/new" element={<CreateAgentPage />} />
          <Route path="/agents/:name" element={<div>the agent's page</div>} />
        </Routes>
      </MemoryRouter>,
    ),
  );
}

// By role and accessible name rather than `getByLabelText`. `Field` puts its hint inside
// the `<label>`, so an input's accessible name is "Name However you would refer to it…" —
// which is correct for a screen reader and means an exact-match query finds nothing. The
// regexes are anchored at the start only, deliberately: they assert the label and say
// nothing about the hint beside it.
const nameBox = () => screen.getByRole("textbox", { name: /^Name/ });
const slugBox = () => screen.getByRole("textbox", { name: /^ID/ }) as HTMLInputElement;
const next = () => screen.getByRole("button", { name: "Continue" });

function type(field: HTMLElement, value: string) {
  fireEvent.change(field, { target: { value } });
}

/** Fill step 1 and move on. */
async function nameIt(name = "Triage bot") {
  type(await screen.findByRole("textbox", { name: /^Name/ }), name);
  fireEvent.click(next());
}

function tick(tool: string) {
  fireEvent.click(screen.getByRole("checkbox", { name: new RegExp(tool) }));
}

/** One derived scope question, on step 3.
 *
 *  Scoped by card rather than queried globally: two ticked tools produce two rows, and
 *  every row has the same two radios. That is the join working, and a test that searched
 *  the page for "Anything of this type" would be ambiguous by construction — the same
 *  lesson 10b's helpers learned from five "found multiple elements" failures. */
function reachCard(resource: string) {
  return within(screen.getByText(resource).closest("section")!);
}

beforeEach(() => {
  sessionStorage.clear();
  vi.mocked(api.listTools).mockReset();
  vi.mocked(api.createAgent).mockReset();
  vi.mocked(api.validateDraft).mockReset();
  vi.mocked(api.agentAccess).mockResolvedValue({ access: [], waiting: [] });
  // 035h: `ShareBox` fetches the tenant's groups, so every test that renders the share
  // sheet as somebody who may share needs an answer here.
  vi.mocked(api.listGroups).mockResolvedValue([]);
  vi.mocked(api.listConnections).mockResolvedValue([]);
  vi.mocked(api.agentVersions).mockResolvedValue([]);
});

describe("the name becomes a slug", () => {
  it("shows what it will be called, rather than applying it silently", async () => {
    open();
    type(await screen.findByRole("textbox", { name: /^Name/ }), "Triage Bot");

    expect(slugBox().value).toBe("triage-bot");
  });

  it("stops following once somebody takes it over", async () => {
    open();
    type(await screen.findByRole("textbox", { name: /^Name/ }), "Triage Bot");
    type(slugBox(), "triage");
    type(nameBox(), "Triage Bot Two");

    expect(slugBox().value).toBe("triage");
  });

  it("will not continue with a name the server would refuse", async () => {
    open();
    type(await screen.findByRole("textbox", { name: /^Name/ }), "Triage Bot");
    type(slugBox(), "Triage Bot");

    expect(next()).toBeDisabled();
    expect(screen.getByText("Invalid ID")).toBeInTheDocument();
    // The rule, said rather than shown as a regex — this is read by the person who typed
    // it, who by assumption does not know what one is.
    expect(screen.getByText(/lowercase letters, digits and single hyphens/)).toBeInTheDocument();
  });

  it("says why it will not continue, rather than only greying the button", async () => {
    open();
    await screen.findByRole("textbox", { name: /^Name/ });
    expect(screen.getByText("Enter a name.")).toBeInTheDocument();
  });
});

describe("a REST-vetted tool is an ordinary connector tool", () => {
  it("is grouped under its connector and grantable, with no wizard code knowing the kind", async () => {
    open();
    await nameIt();

    // The group renders by connector id with the vetter's own description — the
    // wire says "connector" and nothing about protocol, which is 045a's argument.
    expect(await screen.findByText("tracker")).toBeInTheDocument();
    expect(screen.getByText("Acme's issue tracker, plain REST.")).toBeInTheDocument();
    expect(screen.getByText("List issues in a repository.")).toBeInTheDocument();

    tick("tracker_list_issues");
    fireEvent.click(next());

    // And its resource joins the scope step exactly as an MCP tool's would.
    expect(await screen.findByText("github.repo")).toBeInTheDocument();
    expect(screen.getByText(/used by tracker_list_issues/)).toBeInTheDocument();
  });
});

describe("the scope questions are derived from the ticked tools", () => {
  it("asks about a resource only because a tool that touches it was ticked", async () => {
    open();
    await nameIt();
    tick("post_message");
    fireEvent.click(next());

    expect(await screen.findByText("chat.channel")).toBeInTheDocument();
    expect(screen.queryByText("github.repo")).not.toBeInTheDocument();
    // And it says *why* it is asking — the same join the detail page's Through column
    // renders and `_validate_scope_matches_tools` enforces.
    expect(screen.getByText(/used by post_message/)).toBeInTheDocument();
  });

  it("stops asking when the tool is unticked", async () => {
    open();
    await nameIt();
    tick("post_message");
    tick("github_mcp_list_issues");
    fireEvent.click(next());
    expect(await screen.findByText("github.repo")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    tick("github_mcp_list_issues");
    fireEvent.click(next());

    expect(screen.getByText("chat.channel")).toBeInTheDocument();
    expect(screen.queryByText("github.repo")).not.toBeInTheDocument();
  });

  it("never shows anybody a pattern", async () => {
    open();
    await nameIt();
    tick("post_message");
    fireEvent.click(next());
    await screen.findByText("chat.channel");

    // The syntax is not in the interface. Somebody who knows it can still type `org/*`
    // into the box; somebody who does not cannot produce one by accident.
    expect(document.body.textContent).not.toContain("**");
    expect(document.body.textContent).not.toMatch(/wildcard/i);
  });

  it("will not continue with 'only selected' and nothing in it", async () => {
    // A perfectly valid config that denies every call the tool could make: the scope
    // entry exists, so the validator is satisfied, and the agent reads as capable and is
    // not. The one failure the derivation cannot prevent on its own.
    open();
    await nameIt();
    tick("post_message");
    fireEvent.click(next());
    fireEvent.click(
      await screen.findByRole("radio", { name: "Only selected channels" }),
    );

    expect(next()).toBeDisabled();
    expect(screen.getByText(/Add at least one chat.channel/)).toBeInTheDocument();
  });

  it("says what 'All' means in its own voice", async () => {
    open();
    await nameIt();
    tick("post_message");
    fireEvent.click(next());
    fireEvent.click(await screen.findByRole("radio", { name: "All channels" }));

    expect(screen.getByRole("heading", { name: "All channels" })).toBeInTheDocument();
    expect(
      screen.getByText(/change every channel the caller's account can access/),
    ).toBeInTheDocument();
    expect(next()).toBeEnabled();
  });
});

/** Step 081. The fourth step used to be *Ceilings* and it is gone.
 *
 *  It asked for a `limits` block, a `max_tokens` and a `private_runs` flag, and nothing in
 *  this tree reads any of them — `Budget.for_agent` was reached only from
 *  `RunContext.start`, which had no caller, and the door hands the broker a `TokenBudget`
 *  whose `reserve` ignores the tool. Step 084 deleted both; the door's `TokenBudget` is
 *  now the only `Spending` there is. So `max_writes: 0` under *"every write is refused
 *  before it reaches a system"* refused nothing, which is the worst of the four promises
 *  080 section B names because it is a safety control rather than a convenience. */
describe("what the wizard stopped asking for", () => {
  async function toTheEnd() {
    open();
    await nameIt();
    tick("post_message");
    fireEvent.click(next());
    fireEvent.click(await screen.findByRole("radio", { name: "All channels" }));
    fireEvent.click(next());
  }

  it("is four steps, and the fourth is the review", async () => {
    await toTheEnd();

    expect(
      await screen.findByRole("heading", { name: "Resource access" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("listitem", { name: /Ceilings/ })).not.toBeInTheDocument();
  });

  it("offers no per-run ceiling, no answer-length box and no privacy tick", async () => {
    await toTheEnd();
    await screen.findByRole("heading", { name: "Resource access" });

    expect(
      screen.queryByRole("checkbox", { name: /may not change anything/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("textbox", { name: /^Tool calls per run/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("checkbox", { name: /private to them/ }),
    ).not.toBeInTheDocument();
  });

  it("says what does bound it, where somebody is deciding", async () => {
    // A removed control and a removed answer are different things. There *is* a ceiling on
    // a door deployment — per token, per UTC day, `CARNET_MCP_CALLS_PER_DAY` and its two
    // spend siblings — and the review step is where it gets named.
    await toTheEnd();

    const card = (await screen.findByRole("heading", { name: "Limits" }))
      .closest("section")!;
    expect(card.textContent).toMatch(/token/);
    expect(card.textContent).toMatch(/set per token, not per agent/);
  });

  it("sends a config that is a name and a permission list, and nothing else", async () => {
    vi.mocked(api.createAgent).mockResolvedValue({ name: "triage-bot", owner: "user:u1" });
    await toTheEnd();
    fireEvent.click(await screen.findByRole("button", { name: "Create agent" }));

    await waitFor(() => expect(api.createAgent).toHaveBeenCalled());
    const config = vi.mocked(api.createAgent).mock.calls[0][0] as Record<string, unknown>;
    expect(Object.keys(config).sort()).toEqual(["name", "permissions"]);
  });
});

describe("creating it", () => {
  /** Walk the whole wizard and press Create. Returns the config that went on the wire. */
  async function walkThrough() {
    open();
    await nameIt();
    tick("post_message");
    tick("github_mcp_list_issues");
    fireEvent.click(next());

    await screen.findByText("chat.channel");
    fireEvent.click(
      reachCard("chat.channel").getByRole("radio", { name: "All channels" }),
    );
    fireEvent.click(reachCard("github.repo").getByRole("button", { name: "Add a repository" }));
    type(screen.getByLabelText("github.repo 1"), "anthropics/anthropic-sdk-python");
    fireEvent.click(next());

    await screen.findByRole("heading", { name: "Resource access" });
    fireEvent.click(screen.getByRole("button", { name: "Create agent" }));

    await waitFor(() => expect(api.createAgent).toHaveBeenCalled());
    return vi.mocked(api.createAgent).mock.calls[0][0];
  }

  it("posts the config, with the scope it derived", async () => {
    vi.mocked(api.createAgent).mockResolvedValue({ name: "triage-bot", owner: "user:u1" });

    expect(await walkThrough()).toEqual({
      name: "triage-bot",
      permissions: {
        tools: ["post_message", "github_mcp_list_issues"],
        scope: {
          "chat.channel": { write: ["**"] },
          "github.repo": { read: ["anthropics/anthropic-sdk-python"] },
        },
      },
    });
  });

  it("checks the draft with the server before offering the button", async () => {
    open();
    await nameIt();
    fireEvent.click(next());
    fireEvent.click(next());

    expect(await screen.findByRole("heading", { name: "Ready to create" })).toBeInTheDocument();
    expect(api.validateDraft).toHaveBeenCalled();
  });

  it("renders the server's own sentence when the dry run refuses", async () => {
    vi.mocked(api.listTools).mockResolvedValue(CATALOGUE);
    vi.mocked(api.validateDraft).mockRejectedValue(
      new ApiError(422, "agent 'x' scopes jira.project (read), which none of its granted tools touch."),
    );
    render(
      withMe(
        <MemoryRouter>
          <CreateAgentPage />
        </MemoryRouter>,
      ),
    );
    await nameIt();
    fireEvent.click(next());
    fireEvent.click(next());

    expect(await screen.findByRole("heading", { name: "Configuration not accepted" })).toBeInTheDocument();
    expect(screen.getByText(/none of its granted tools touch/)).toBeInTheDocument();
  });

  it("sends a taken name back to step 1 with the reason", async () => {
    vi.mocked(api.createAgent).mockRejectedValue(
      new ApiError(409, "this organisation already has an agent called 'triage-bot'."),
    );
    await walkThrough();

    // Back on the name step, because that is where the fixable field is — not left on a
    // review screen holding a message about something not on it.
    expect(await screen.findByRole("textbox", { name: /^ID/ })).toBeInTheDocument();
    expect(screen.getByText(/already has an agent called/)).toBeInTheDocument();
  });

  it("keeps the draft when the create is refused, and clears it when it is not", async () => {
    vi.mocked(api.createAgent).mockRejectedValue(new ApiError(409, "taken"));
    await walkThrough();
    expect(sessionStorage.getItem("carnet.draft.v1")).toContain("triage-bot");

    vi.mocked(api.createAgent).mockResolvedValue({ name: "triage-bot-2", owner: "user:u1" });
    type(slugBox(), "triage-bot-2");
    // Forward through the steps rather than jumping to Review. The step buttons only go
    // backwards — skipping ahead past an unanswered step is how somebody arrives at the
    // review screen with a scope row they never filled in.
    for (let i = 0; i < 3; i++) fireEvent.click(next());
    fireEvent.click(await screen.findByRole("button", { name: "Create agent" }));

    await waitFor(() =>
      expect(sessionStorage.getItem("carnet.draft.v1")).toBeNull(),
    );
  });
});

describe("the review step and the agent's own page are one screen", () => {
  /** The permission model as each screen renders it, with the card's own title removed.
   *
   *  The title line is the only difference the two are permitted — the hint reads "as
   *  stored" against "as it will be stored", present tense against future — and it is a
   *  prop rather than a branch precisely so that a second difference would take an argument. */
  function reachBody(): string {
    const card = screen
      .getByRole("heading", { name: "Resource access" })
      .closest("section")!;
    const clone = card.cloneNode(true) as HTMLElement;
    clone.querySelector(".card-title")!.remove();
    return clone.innerHTML;
  }

  it("renders the same agent identically, because it is the same component", async () => {
    // Step 4, over a draft.
    open();
    await nameIt();
    tick("post_message");
    tick("github_mcp_list_issues");
    fireEvent.click(next());
    await screen.findByText("chat.channel");
    fireEvent.click(
      reachCard("chat.channel").getByRole("radio", { name: "All channels" }),
    );
    fireEvent.click(reachCard("github.repo").getByRole("button", { name: "Add a repository" }));
    type(screen.getByLabelText("github.repo 1"), "anthropics/anthropic-sdk-python");
    fireEvent.click(next());
    await screen.findByRole("heading", { name: "Resource access" });

    const inTheForm = reachBody();
    screen.getByRole("button", { name: "Create agent" }); // still on the review step
    cleanupBetween();

    // The detail page, over the agent that draft would have created.
    const created: AgentDetail = {
      name: "triage-bot",
      runtime: "simple",
      tools: ["post_message", "github_mcp_list_issues"],
      valid: true,
      error: null,
      system: "You summarise open issues.",
      scope: {
        "chat.channel": { write: ["**"] },
        "github.repo": { read: ["anthropics/anthropic-sdk-python"] },
      },
      limits: {},
      updated_at: "2026-08-08T04:12:33.482391+00:00",
      your_role: "owner",
      version: 1,
      config: {},
    };
    vi.mocked(api.getAgent).mockResolvedValue(created);
    vi.mocked(api.listTools).mockResolvedValue(CATALOGUE);
    vi.mocked(api.doorActivity).mockResolvedValue({ calls: 0, last_call_at: null });
    render(
      withMe(
        <MemoryRouter initialEntries={["/agents/triage-bot"]}>
          <Routes>
            <Route path="/agents/:name" element={<AgentDetailPage />} />
          </Routes>
        </MemoryRouter>,
      ),
    );
    await screen.findByRole("heading", { name: "Resource access" });

    expect(reachBody()).toBe(inTheForm);
  });

  it("shows the write, marked, on the review step too", async () => {
    // A sanity check on the diff above: two empty strings are also identical.
    open();
    await nameIt();
    tick("post_message");
    fireEvent.click(next());
    fireEvent.click(await screen.findByRole("radio", { name: "All channels" }));
    fireEvent.click(next());

    const card = (await screen.findByRole("heading", { name: "Resource access" }))
      .closest("section")!;
    expect(within(card).getByText("Write tools")).toBeInTheDocument();
    expect(
      within(card).getByText(/One tool that can change data in the connected system/),
    ).toBeInTheDocument();
  });
});

/** Unmount the wizard so the two screens are not both in the document at once.
 *
 *  `cleanup` runs after each test, not between two renders inside one — and the diff
 *  above needs both, one at a time. */
function cleanupBetween() {
  document.body.innerHTML = "";
}

describe("a tool that was ticked and then withdrawn", () => {
  /** **The wizard was a dead end, and it was found by somebody using it.**
   *
   * A draft lives in `sessionStorage` and outlives navigation and reloads. The catalogue
   * does not: an administrator can re-vet a tool under a different local name whenever
   * they like, which is exactly what `storage.vet_tool`'s upsert is for. When that
   * happened mid-draft, the review step correctly refused to create the agent with the
   * validator's own sentence and told the person to *"go back and change it"* — and going
   * back could not change it, because every control on the tools step is rendered from
   * the catalogue and a withdrawn name has no control. The only escape was clearing
   * session storage or closing the tab.
   *
   * Hit for real while approving DeepWiki's three tools, re-vetting them to attach a
   * resource, and returning to a draft that still held the old names.
   */
  function draftWithAWithdrawnTool() {
    sessionStorage.setItem(
      "carnet.draft.v1",
      JSON.stringify({ tools: ["github_mcp_list_issues", "deepwiki_read_content"] }),
    );
  }

  it("is named, because it has no tick box to find it by", async () => {
    draftWithAWithdrawnTool();
    open();
    await nameIt();

    expect(await screen.findByText(/Selected tools no longer available/)).toBeInTheDocument();
    expect(screen.getByText(/deepwiki_read_content/)).toBeInTheDocument();
    // The thing that made it a dead end: no checkbox exists for it.
    expect(
      screen.queryByRole("checkbox", { name: /deepwiki_read_content/ }),
    ).not.toBeInTheDocument();
  });

  it("can be removed, and removing it leaves the valid grants alone", async () => {
    draftWithAWithdrawnTool();
    open();
    await nameIt();

    fireEvent.click(await screen.findByRole("button", { name: /^Remove/ }));

    await waitFor(() =>
      expect(screen.queryByText(/Selected tools no longer available/)).not.toBeInTheDocument(),
    );
    // The tool that is still in the catalogue stays ticked — the fix must not clear the
    // draft, which is what closing the tab did.
    expect(screen.getByRole("checkbox", { name: /github_mcp_list_issues/ })).toBeChecked();
  });

  it("says nothing when every ticked tool is still in the catalogue", async () => {
    open();
    await nameIt();
    tick("github_mcp_list_issues");

    expect(screen.queryByText(/Selected tools no longer available/)).not.toBeInTheDocument();
  });
});

describe("what the wizard does not ask", () => {
  // **The door reads the permissions, and nothing else.** That sentence used to end "and
  // the ceilings", which was false when it was written in 078 and is the fourth defect
  // step 081 found: `limits` reached enforcement only through `Budget.for_agent` ←
  // `RunContext.start`, which nothing called — both deleted by 084. There is no briefing
  // to write, no model to
  // choose and no ceiling to set here: an agent is a permission list.
  it("asks for a name alone on step 1, and continues", async () => {
    open();

    type(await screen.findByRole("textbox", { name: /^Name/ }), "Triage bot");
    expect(
      screen.queryByRole("heading", { name: "What is it for?" }),
    ).not.toBeInTheDocument();
    fireEvent.click(next());

    expect(
      await screen.findByRole("checkbox", { name: /post_message/ }),
    ).toBeInTheDocument();
  });

  it("offers no model chooser, and no longer offers a ceiling either", async () => {
    open();
    type(await screen.findByRole("textbox", { name: /^Name/ }), "Triage bot");
    fireEvent.click(next());
    tick("post_message");
    fireEvent.click(next());
    await screen.findByText("chat.channel");
    fireEvent.click(
      reachCard("chat.channel").getByRole("radio", { name: "All channels" }),
    );
    fireEvent.click(next());

    // Step 4 is the review. Until 081 it was *Ceilings*, whose controls all wrote config
    // keys nothing in this tree reads — see the describe above.
    expect(
      await screen.findByRole("heading", { name: "Resource access" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "May it change anything?" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "How capable should it be?" }),
    ).not.toBeInTheDocument();
  });

});


// --- 092: finding a tool in a catalogue that has outgrown one screen ------------------

describe("the tools step, at the size a real deployment reaches", () => {
  /** A catalogue with enough in it that the filter appears — the threshold is 8, and
   *  below it a search box is a control that costs a glance and saves nothing. */
  function big() {
    const tools = Array.from({ length: 12 }, (_, i) => ({
      name: `github_tool_${i}`,
      remote_name: `tool_${i}`,
      description: i === 3 ? "Read a calendar entry." : `Does thing ${i}.`,
      note: "",
      effect: "read" as const,
      identity: "service" as const,
      resources: [],
      max_response_bytes: null,
      vetted_by: "",
      vetted_at: "",
    }));
    return [
      { origin: "connector" as const, id: "github", description: "", tools },
      {
        origin: "connector" as const,
        id: "jira",
        description: "",
        tools: [
          {
            name: "jira_list_issues",
            remote_name: "list_issues",
            description: "List issues.",
            note: "",
            effect: "read" as const,
            identity: "service" as const,
            resources: [],
            max_response_bytes: null,
            vetted_by: "",
            vetted_at: "",
          },
        ],
      },
    ];
  }

  async function onTools() {
    open(big());
    await nameIt();
    await screen.findByText(/of 13 selected/);
  }

  it("says how many are chosen out of how many there are", async () => {
    await onTools();
    expect(screen.getByText("0 of 13 selected")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("checkbox", { name: /jira_list_issues/ }));
    expect(screen.getByText("1 of 13 selected")).toBeInTheDocument();
  });

  it("narrows by name, by description and by which app it came from", async () => {
    await onTools();
    const box = screen.getByRole("searchbox", { name: /Find a tool/ });

    fireEvent.change(box, { target: { value: "jira" } });
    expect(screen.getByRole("checkbox", { name: /jira_list_issues/ })).toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: /github_tool_0/ })).not.toBeInTheDocument();

    // By description, which is the only thing a person who does not know the tool's
    // name has to go on.
    fireEvent.change(box, { target: { value: "calendar" } });
    expect(screen.getByRole("checkbox", { name: /github_tool_3/ })).toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: /github_tool_2/ })).not.toBeInTheDocument();
  });

  it("never hides something already ticked", async () => {
    // **The one rule this filter has.** A filter that can conceal a granted write is a
    // filter that will, and the number above the list is only true if everything it
    // counts can still be seen and unticked.
    await onTools();
    fireEvent.click(screen.getByRole("checkbox", { name: /jira_list_issues/ }));
    fireEvent.change(screen.getByRole("searchbox", { name: /Find a tool/ }), {
      target: { value: "zzz-matches-nothing" },
    });

    expect(screen.getByRole("checkbox", { name: /jira_list_issues/ })).toBeChecked();
    expect(screen.queryByRole("checkbox", { name: /github_tool_0/ })).not.toBeInTheDocument();
  });

  it("says so when a filter matches nothing at all", async () => {
    await onTools();
    fireEvent.change(screen.getByRole("searchbox", { name: /Find a tool/ }), {
      target: { value: "zzz-matches-nothing" },
    });

    expect(screen.getByText(/Nothing matches/)).toBeInTheDocument();
  });

  it("offers no search box over a catalogue small enough to read", async () => {
    open();
    await nameIt();
    await screen.findByText("List issues in a repository.");

    expect(screen.queryByRole("searchbox")).not.toBeInTheDocument();
  });
});
