/** The screen 10b exists for: can a person tell what an agent may do to their systems?
 *
 * These assert **sentences**, not markup. The thing this chunk delivers is a reader
 * being able to say out loud what an agent may change, and the failure mode it guards
 * against is not a layout regression — it is a screen that renders a write and a read as
 * two indistinguishable names, which is what 10a shipped.
 *
 * The first test below is the one that would have caught the bug this chunk shipped: the
 * singular branch read "One tool that **alter** a system", on the most important line of
 * the page, and it survived a typecheck, a build, a 916-test backend suite and a code
 * review. It was found by looking at the page in a browser.
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
      getAgent: vi.fn(),
      listTools: vi.fn(),
      // 10d puts the share sheet on this page, so it fetches too. Stubbed empty here:
      // the sheet has its own tests, and a page test that also asserted it would be two
      // tests in one and would fail for two reasons.
      agentAccess: vi.fn(),
      listGroups: vi.fn(),
      // 7b puts `ConnectionNotice` on this page, which asks whether the viewer has
      // connected the connectors this agent's tools come from. Stubbed empty for the
      // same reason the share sheet is: it has its own tests, and a page test that also
      // asserted it would fail for two reasons.
      listConnections: vi.fn(),
      // 021 puts the history card here, which fetches for the same reason and is stubbed
      // for the same reason: it has its own tests.
      agentVersions: vi.fn(),
      myTokens: vi.fn(),
      // 044 puts the connect card here, which asks whether anything has knocked on the
      // door for this agent. Stubbed at zero for the reason all of the above are: it
      // has its own tests, in ConnectCard.test.tsx.
      doorActivity: vi.fn(),
      deleteAgent: vi.fn(),
      renameAgent: vi.fn(),
      shareAgent: vi.fn(),
      unshareAgent: vi.fn(),
    },
  };
});

import AgentDetailPage from "./AgentDetailPage";
import { MeContext } from "../../lib/me";
import { api, ApiError } from "../../lib/api";
import type { AgentDetail, ToolGroup } from "../../lib/types";

// The real payloads, trimmed. Taken from `GET /tools` and `GET /agents/minimal` against
// the demo database rather than invented, so a change to the wire shape shows up here.
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
  name: "github_mcp_list_issues",
  remote_name: "list_issues",
  description: "List issues in a GitHub repository.",
  note: "Scope it to the repositories a team actually owns.",
  effect: "read" as const,
  resources: [{ type: "github.repo" }],
  max_response_bytes: 262144,
  identity: "service" as const,
  vetted_by: "",
  vetted_at: "2026-08-07T15:50:20.965049+00:00",
};

const ADD_COMMENT = {
  ...LIST_ISSUES,
  name: "github_mcp_add_issue_comment",
  remote_name: "add_issue_comment",
  description: "Add a comment to an issue in a GitHub repository.",
  note: "",
  effect: "write" as const,
};

const CATALOGUE: ToolGroup[] = [
  { origin: "builtin", id: "", description: "Tools that ship with the platform.", tools: [POST_MESSAGE] },
  { origin: "connector", id: "github-mcp", description: "GitHub.", tools: [LIST_ISSUES, ADD_COMMENT] },
];

const MINIMAL: AgentDetail = {
  name: "minimal",
  runtime: "simple",
  tools: ["github_mcp_list_issues", "post_message"],
  valid: true,
  error: null,
  system: "You summarize GitHub issues.",
  scope: {
    "github.repo": { read: ["anthropics/anthropic-sdk-python"] },
    "chat.channel": { write: ["#eng"] },
  },
  updated_at: "2026-08-08T04:12:33.482391+00:00",
  // `user`, so the edit and delete controls are absent by default and the tests below
  // read the screen every reader sees rather than the owner's.
  your_role: "user",
  version: 1,
  config: {},
  limits: { max_calls: 3 },
};

function show(
  agent: Partial<AgentDetail> = {},
  catalogue: ToolGroup[] | Error = CATALOGUE,
) {
  vi.mocked(api.getAgent).mockResolvedValue({ ...MINIMAL, ...agent });
  vi.mocked(api.listTools).mockImplementation(
    catalogue instanceof Error
      ? () => Promise.reject(catalogue)
      : () => Promise.resolve(catalogue),
  );

  // The page reads `/me` from the shell through context, and the shell is not in this
  // tree — so it is supplied here.
  render(
    <MeContext.Provider
      value={{ me: ME, settled: true }}
    >
      <MemoryRouter initialEntries={["/agents/minimal"]}>
        <Routes>
          <Route path="/agents/:name" element={<AgentDetailPage />} />
        </Routes>
      </MemoryRouter>
    </MeContext.Provider>,
  );
}

const ME = {
  principal: "user:u_9311",
  kind: "user",
  email: "priya@acme.com",
  display_name: "Priya",
  admin: false,
};

/** The "Resource access" card. */
function reach() {
  return screen.getByRole("heading", { name: "Resource access" }).closest("section")!;
}

/** The tool blocks, in the order they are rendered.
 *
 *  Queried by structure rather than by text, because a granted tool's name deliberately
 *  appears **twice** on this page — once as the thing itself and once in the Through
 *  column of the resources table. That duplication is the feature, so a test that
 *  searches the whole card for a name is ambiguous by construction. */
function toolBlocks(): HTMLElement[] {
  return Array.from(reach().querySelectorAll<HTMLElement>(".tool"));
}

function toolNames(): string[] {
  return toolBlocks().map((block) => block.querySelector(".name")!.textContent!);
}

function toolBlock(name: string): HTMLElement {
  const found = toolBlocks().find(
    (block) => block.querySelector(".name")!.textContent === name,
  );
  if (!found) throw new Error(`no tool block for ${name}; have ${toolNames().join(", ")}`);
  return found;
}

beforeEach(() => {
  vi.mocked(api.getAgent).mockReset();
  vi.mocked(api.listTools).mockReset();
  vi.mocked(api.agentAccess).mockReset();
  vi.mocked(api.agentAccess).mockResolvedValue({ access: [], waiting: [] });
  // 035h: `ShareBox` fetches the tenant's groups, so every test that renders the share
  // sheet as somebody who may share needs an answer here.
  vi.mocked(api.listGroups).mockResolvedValue([]);
  vi.mocked(api.listConnections).mockReset();
  vi.mocked(api.listConnections).mockResolvedValue([]);
  vi.mocked(api.agentVersions).mockReset();
  vi.mocked(api.agentVersions).mockResolvedValue([]);
  vi.mocked(api.myTokens).mockReset();
  vi.mocked(api.myTokens).mockResolvedValue([]);
  vi.mocked(api.doorActivity).mockReset();
  vi.mocked(api.doorActivity).mockResolvedValue({ calls: 0, last_call_at: null });
});

describe("which tools write", () => {
  it("states the writes first, and separately from the reads", async () => {
    show();

    // Both headings, and the write one above the read one. Burying two writes among
    // nine reads answers "what can this change" only for somebody who reads all eleven.
    const change = await screen.findByRole("heading", { name: "Write tools" });
    const read = screen.getByRole("heading", { name: "Read tools" });
    expect(change.compareDocumentPosition(read)).toBe(Node.DOCUMENT_POSITION_FOLLOWING);

    expect(toolNames()).toEqual(["post_message", "github_mcp_list_issues"]);
  });

  it("labels each tool with its effect", async () => {
    show();
    await screen.findByRole("heading", { name: "Write tools" });

    expect(within(toolBlock("post_message")).getByText("write")).toBeInTheDocument();
    expect(
      within(toolBlock("github_mcp_list_issues")).getByText("read"),
    ).toBeInTheDocument();
  });

  it("agrees with itself about number — one tool is singular", async () => {
    // The bug this chunk shipped: "One tool that alter a system" — the singular sentence
    // wearing the plural verb. Pinned as: the singular sentence exact, the plural absent.
    show({ tools: ["post_message"], scope: { "chat.channel": { write: ["#eng"] } } });

    expect(
      await screen.findByText("One tool that can change data in the connected system."),
    ).toBeInTheDocument();
    expect(screen.queryByText(/tools that can change data/)).not.toBeInTheDocument();
  });

  it("agrees with itself about number — two tools are plural", async () => {
    show({
      tools: ["post_message", "github_mcp_add_issue_comment"],
      scope: { "chat.channel": { write: ["#eng"] }, "github.repo": { write: ["a/b"] } },
    });

    expect(
      await screen.findByText(/2 tools that can change data in connected systems/),
    ).toBeInTheDocument();
  });

  it("says nothing about changing things when an agent only reads", async () => {
    // A read-only agent must not carry a heading warning about writes it does not have.
    show({
      tools: ["github_mcp_list_issues"],
      scope: { "github.repo": { read: ["a/b"] } },
    });

    expect(await screen.findByRole("heading", { name: "Read tools" })).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Write tools" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/One tool that reads data and changes nothing/),
    ).toBeInTheDocument();
  });
});

describe("what each tool is", () => {
  it("shows the description the connector admin stored", async () => {
    show();
    expect(
      await screen.findByText("List issues in a GitHub repository."),
    ).toBeInTheDocument();
    expect(screen.getByText("Post a message to a team chat channel.")).toBeInTheDocument();
  });

  it("shows the note, which is ours rather than the vendor's", async () => {
    show();
    expect(
      await screen.findByText("Scope it to the repositories a team actually owns."),
    ).toBeInTheDocument();
  });

  it("says a description is absent rather than leaving a gap", async () => {
    // Every row vetted before migration 018 has none, and a blank where a sentence
    // belongs reads as a rendering bug rather than as a fact about the row.
    show({}, [
      { origin: "builtin", id: "", description: "", tools: [{ ...POST_MESSAGE, description: "" }] },
      { origin: "connector", id: "github-mcp", description: "", tools: [LIST_ISSUES] },
    ]);

    expect(
      await screen.findByText("No description."),
    ).toBeInTheDocument();
  });

  it("says where a tool came from", async () => {
    show();
    await screen.findByRole("heading", { name: "Write tools" });
    expect(within(toolBlock("post_message")).getByText("built in")).toBeInTheDocument();
    expect(
      within(toolBlock("github_mcp_list_issues")).getByText("from github-mcp"),
    ).toBeInTheDocument();
  });

  it("never renders argument names — decision 2, at the last place it could leak", async () => {
    show();
    await screen.findByRole("heading", { name: "Write tools" });
    // `github.repo` is composed from `owner` and `repo`; a client that learned those
    // could build a scope out of them, which the resource type exists to prevent.
    expect(reach().textContent).not.toMatch(/\bowner\b/);
    expect(reach().textContent).not.toMatch(/template/);
  });
});

describe("the resources table", () => {
  it("joins each scope row to the granted tools that use it", async () => {
    show();
    await screen.findByRole("heading", { name: "Write tools" });

    // Scoped to the table: a resource type appears in its tool's block too, which is
    // the same deliberate duplication as the tool names.
    const table = within(reach().querySelector("table")!);

    const repo = table.getByText("github.repo").closest("tr")!;
    expect(within(repo).getByText("anthropics/anthropic-sdk-python")).toBeInTheDocument();
    expect(within(repo).getByText("github_mcp_list_issues")).toBeInTheDocument();

    const channel = table.getByText("chat.channel").closest("tr")!;
    expect(within(channel).getByText("#eng")).toBeInTheDocument();
    expect(within(channel).getByText("post_message")).toBeInTheDocument();
  });

  it("marks a scope entry no granted tool touches", async () => {
    // `agents.validate` refuses this in both directions, so a *valid* agent cannot show
    // it — but a broken one is rendered rather than hidden, the same call `GET /agents`
    // makes about listing an invalid row.
    show({
      tools: ["post_message"],
      scope: { "chat.channel": { write: ["#eng"] }, "jira.project": { read: ["ENG"] } },
    });

    const stale = (await screen.findByText("jira.project")).closest("tr")!;
    expect(within(stale).getByText("no granted tool uses this")).toBeInTheDocument();
  });

  it("says no selected resources means any resource the caller can reach", async () => {
    // `list_issues` declares `github.repo`, so the open-access sentence is the true one.
    show({ tools: ["github_mcp_list_issues"], scope: {} });
    expect(
      await screen.findByText(/No resources are selected.*any resource the caller's account can reach/),
    ).toBeInTheDocument();
  });
});

describe("when the catalogue is not there", () => {
  it("still lists the tools, and says which half is missing", async () => {
    // Degraded rather than wrong. The names are the agent's own config and are still
    // true; what is absent is the annotation saying which of them change anything, and
    // silently dropping that would read as "none of these write".
    show({}, new ApiError(503, "the service cannot reach its database"));

    expect(
      await screen.findByText(/could not be loaded. Tool effects are not shown/),
    ).toBeInTheDocument();
    expect(screen.getByText("post_message")).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Write tools" }),
    ).not.toBeInTheDocument();
  });

  it("marks a granted tool the catalogue does not describe", async () => {
    // A connector withdrawn underneath a live agent.
    show({}, [
      { origin: "builtin", id: "", description: "", tools: [POST_MESSAGE] },
    ]);

    expect(await screen.findByText(/Granted, and no longer available/)).toBeInTheDocument();
    expect(
      screen.getByText(/github_mcp_list_issues is granted to this agent and no longer available/),
    ).toBeInTheDocument();
  });
});

describe("an agent granted nothing", () => {
  it("says so plainly rather than showing an empty list", async () => {
    show({ tools: [], scope: {} });
    expect(
      await screen.findByText("This agent has no tools."),
    ).toBeInTheDocument();
  });
});

/** Step 081. What is stored and not read, in one card that does not claim otherwise.
 *
 *  This replaces three describes' worth of assertions about *Instructions*, *The answer it
 *  must give* and *Ceilings — per run*. Each of those cards rendered a stored value under a
 *  heading implying something enforced it, and nothing in this tree does: the door reads
 *  `permissions.tools` and `permissions.scope` and no other config key. The values are
 *  still shown — somebody who authored a schema over the API has to be able to read back
 *  what they stored — under a heading that says what is true about them. */
describe("what is stored and not read here", () => {
  const SCHEMA = {
    type: "object",
    properties: { summary: { type: "string" } },
    required: ["summary"],
    additionalProperties: false,
  };

  function card() {
    return screen.getByRole("heading", { name: "Unused settings" })
      .closest("section")!;
  }

  it("shows every unread field the config carries, and says nothing acts on it", async () => {
    show({
      config: {
        name: "minimal",
        system: "You summarise.",
        runtime: "simple",
        private_runs: true,
        limits: { max_writes: 0 },
        output: { schema: SCHEMA },
      },
    });

    await screen.findByRole("heading", { name: "Unused settings" });
    expect(within(card()).getByText("Instructions")).toBeInTheDocument();
    expect(within(card()).getByText("Runtime tier")).toBeInTheDocument();
    expect(within(card()).getByText("Privacy setting")).toBeInTheDocument();
    expect(within(card()).getByText("Limits")).toBeInTheDocument();
    expect(within(card()).getByText("Answer schema")).toBeInTheDocument();
    // The one claim the card makes: nothing at call time reads these.
    expect(
      within(card()).getByText(/The MCP endpoint does not read them/),
    ).toBeInTheDocument();
  });

  it("renders the stored schema pretty-printed, which is why it is still shown", async () => {
    // The reader half of 024's register row, kept: a schema authored by `--seed` arrives
    // as whatever one line it was written on, and being able to read it is the whole ask.
    show({ config: { name: "minimal", output: { schema: SCHEMA } } });

    await screen.findByRole("heading", { name: "Unused settings" });
    // The whole `output` section, not the schema unwrapped from it. What is shown is the
    // stored config key verbatim — unwrapping would be this card having an opinion about
    // the shape of a value it is explicitly not reading.
    const rendered = [...card().querySelectorAll("pre")].map((el) => el.textContent);
    expect(rendered).toContain(JSON.stringify({ schema: SCHEMA }, null, 2));
  });

  it("renders a system prompt as prose rather than as quoted JSON", async () => {
    show({ config: { name: "minimal", system: "You summarise." } });

    await screen.findByRole("heading", { name: "Unused settings" });
    expect(within(card()).getByText("You summarise.")).toBeInTheDocument();
  });

  it("shows a stored value that is falsy, because stored is the question it answers", async () => {
    // **Presence, not truthiness, and the distinction is load-bearing.** `private_runs:
    // false` and `limits: {}` are keys somebody wrote; filtering on the value would hide
    // them and the card would be answering *"is this set to something interesting"* when
    // the heading promises *"what is stored"*. The cost is a blank row for a `system` that
    // was stored as the empty string, which is accepted — it is also a key somebody wrote.
    show({
      config: {
        name: "minimal",
        private_runs: false,
        limits: {},
        max_tokens: 0,
      },
    });

    await screen.findByRole("heading", { name: "Unused settings" });
    expect(within(card()).getByText("Privacy setting")).toBeInTheDocument();
    expect(within(card()).getByText("Limits")).toBeInTheDocument();
    expect(within(card()).getByText("Answer-length limit")).toBeInTheDocument();
    const rendered = [...card().querySelectorAll("pre")].map((el) => el.textContent);
    expect(rendered).toEqual(expect.arrayContaining(["false", "{}", "0"]));
  });

  it("renders no card at all for a config carrying none of them", async () => {
    // The majority case for an agent created since 078, and the precedent both cards
    // this replaces already set: absent rather than a card announcing a non-fact.
    show({ config: { name: "minimal", permissions: { tools: [], scope: {} } } });

    await screen.findByRole("heading", { name: "Resource access" });
    expect(
      screen.queryByRole("heading", { name: "Unused settings" }),
    ).not.toBeInTheDocument();
  });

  it("no longer claims a schema is checked, or that a ceiling is per run", async () => {
    // The defect this step exists for, asserted as absence. `every run is checked against
    // this before it is called complete` was a hint on a card about a schema nothing
    // reads, and `Ceilings — per run` sat over a `limits` block nothing enforces.
    show({
      config: { name: "minimal", limits: { max_writes: 0 }, output: { schema: SCHEMA } },
    });

    await screen.findByRole("heading", { name: "Unused settings" });
    expect(screen.queryByText(/every run is checked against this/)).not.toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "The answer it must give" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Ceilings" })).not.toBeInTheDocument();
  });
});

/** Step 035i. Rename, which is `owner` — and the ladder is the point.
 *
 *  `grants.require` answers **404** for ungranted, held-too-low and absent alike, so a
 *  Rename button rendered for an editor produces *"no agent named 'minimal'"* about the
 *  agent on screen. The first two tests are the ones that matter. */
describe("renaming", () => {
  async function openBox() {
    await screen.findByRole("button", { name: "Rename" });
    await userEvent.click(screen.getByRole("button", { name: "Rename" }));
    return screen.getByRole("heading", { name: "Rename minimal?" }).closest(".notice") as HTMLElement;
  }

  it("offers no Rename to an editor, who would be refused", async () => {
    show({ your_role: "editor" });

    // Edit is a link (it navigates); Rename and Delete are buttons on this page.
    expect(await screen.findByRole("link", { name: "Edit" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Rename" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
  });

  it("offers no Rename to a user, who has no toolbar at all", async () => {
    show({ your_role: "user" });

    await screen.findByRole("heading", { name: "Resource access" });
    expect(screen.queryByRole("button", { name: "Rename" })).not.toBeInTheDocument();
  });

  it("says what survives and what breaks, in that order", async () => {
    show({ your_role: "owner" });
    await openBox();

    // Both halves. The survival half first, because saying only the breakage is what
    // makes people delete the agent and rebuild it — the operation a rename exists to
    // stop being.
    const kept = screen.getByText("Grants, history and sharing are kept.");
    const breaks = screen.getByText(/stop working. There is no redirect/);
    expect(kept).toBeInTheDocument();
    expect(breaks).toBeInTheDocument();
    expect(kept.compareDocumentPosition(breaks)).toBe(Node.DOCUMENT_POSITION_FOLLOWING);
  });

  it("shows the two addresses as they will read, live", async () => {
    show({ your_role: "owner" });
    await openBox();

    await userEvent.clear(screen.getByLabelText(/New name/));
    await userEvent.type(screen.getByLabelText(/New name/), "support-triage");

    expect(screen.getByText("/agents/minimal → /agents/support-triage")).toBeInTheDocument();
  });

  it("blocks the name it already has, rather than earning the server's paragraph", async () => {
    show({ your_role: "owner" });
    await openBox();

    // The default state of this form: opened, unchanged, submitted.
    expect(screen.getByRole("button", { name: "Rename" })).toBeDisabled();
    expect(screen.getByText("The name is already minimal.")).toBeInTheDocument();
    expect(api.renameAgent).not.toHaveBeenCalled();
  });

  it("blocks an empty name, which is the one refusal the server cannot word", async () => {
    show({ your_role: "owner" });
    await openBox();
    await userEvent.clear(screen.getByLabelText(/New name/));

    expect(screen.getByRole("button", { name: "Rename" })).toBeDisabled();
    expect(screen.getByText("Enter the new name.")).toBeInTheDocument();
  });

  it("blocks a name that is not a slug, in the words the server would use", async () => {
    show({ your_role: "owner" });
    await openBox();
    await userEvent.clear(screen.getByLabelText(/New name/));
    await userEvent.type(screen.getByLabelText(/New name/), "Triage Bot");

    expect(screen.getByRole("button", { name: "Rename" })).toBeDisabled();
    expect(screen.getByText(/lowercase letters, digits and single hyphens/)).toBeInTheDocument();
  });

  it("does NOT pre-empt a reserved name — the server's sentence is the point", async () => {
    // 035g decision 2's line. `validate` is a usable slug and an unusable agent name, and
    // only the server knows the second thing.
    vi.mocked(api.renameAgent).mockRejectedValue(
      new ApiError(
        422,
        "'validate' is reserved and cannot be used as an agent name. It is already a path in this product, so an agent called that would have a URL that means two things. Any other name is fine.",
      ),
    );
    show({ your_role: "owner" });
    await openBox();
    await userEvent.clear(screen.getByLabelText(/New name/));
    await userEvent.type(screen.getByLabelText(/New name/), "validate");

    expect(screen.getByRole("button", { name: "Rename" })).toBeEnabled();
    await userEvent.click(screen.getByRole("button", { name: "Rename" }));

    expect(
      await screen.findByText(/is reserved and cannot be used as an agent name/),
    ).toBeInTheDocument();
    // **Not** `Failure`'s 422, which would title it "The server would not accept that
    // request" and send the reader to look at their query string — about a name they
    // typed into a box. Asserted negatively, because that is the failure that would
    // otherwise look like a pass.
    //
    // Retitled with `Failure` itself in 066; asserting the *old* sentence here would
    // have gone on passing while the component rendered, which is the way a negative
    // assertion rots.
    expect(
      screen.queryByText("The server would not accept that request"),
    ).not.toBeInTheDocument();
  });

  it("renders a 409 verbatim and does not navigate", async () => {
    vi.mocked(api.renameAgent).mockRejectedValue(
      new ApiError(409, "an agent named 'triage' already exists"),
    );
    show({ your_role: "owner" });
    await openBox();
    await userEvent.clear(screen.getByLabelText(/New name/));
    await userEvent.type(screen.getByLabelText(/New name/), "triage");
    await userEvent.click(screen.getByRole("button", { name: "Rename" }));

    expect(
      await screen.findByText("an agent named 'triage' already exists"),
    ).toBeInTheDocument();
    // Still on the box, still holding what they typed, so the fix is one edit away.
    expect(screen.getByLabelText(/New name/)).toHaveValue("triage");
    expect(screen.queryByText(/Request failed \(409\)/)).not.toBeInTheDocument();
  });

  it("sends new_name and nothing else, with no precondition", async () => {
    vi.mocked(api.renameAgent).mockResolvedValue({ ...MINIMAL, name: "support-triage" });
    show({ your_role: "owner" });
    await openBox();
    await userEvent.clear(screen.getByLabelText(/New name/));
    await userEvent.type(screen.getByLabelText(/New name/), "support-triage");
    await userEvent.click(screen.getByRole("button", { name: "Rename" }));

    // Two arguments. `updated_at` is deliberately not among them — this is the one write
    // on an agent that takes no `If-Match`, and the neighbouring `updateAgent` takes one.
    await waitFor(() =>
      expect(api.renameAgent).toHaveBeenCalledWith("minimal", "support-triage"),
    );
  });

  it("closes without renaming when the name is kept", async () => {
    show({ your_role: "owner" });
    const box = await openBox();
    await userEvent.click(within(box).getByRole("button", { name: "Cancel" }));

    expect(screen.queryByRole("heading", { name: "Rename minimal?" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rename" })).toBeInTheDocument();
    expect(api.renameAgent).not.toHaveBeenCalled();
  });
});


describe("the page is the permission list", () => {
  it("renders the resource access and the sheet, and nothing that runs anything", async () => {
    show();

    expect(
      await screen.findByRole("heading", { name: "Resource access" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Write tools" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Run it" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /Schedules/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /Triggers/ })).not.toBeInTheDocument();
  });
});
