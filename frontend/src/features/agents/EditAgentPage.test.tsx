/** The edit screen, and the two properties 10d is actually about.
 *
 * **A save must not delete a field nobody asked about**, and **a save from a version
 * that is gone must not land.** Both fail silently in the shape this codebase keeps
 * finding: the first leaves a stored config quietly missing two keys, and the second
 * reverts somebody's scope narrowing with nothing recording that it happened.
 *
 * `draft.test.ts` asserts the patch this screen builds; this asserts that the screen
 * sends that patch, with the version it was built from, and what it does when the server
 * refuses.
 */

import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return {
    ...actual,
    api: { getAgent: vi.fn(), listTools: vi.fn(), updateAgent: vi.fn() },
  };
});

import EditAgentPage from "./EditAgentPage";
import { api, ApiError } from "../../lib/api";
import { MeContext } from "../../lib/me";
import type { AgentDetail, ToolGroup } from "../../lib/types";

function tool(name: string, effect: "read" | "write", resources: string[]) {
  return {
    name,
    remote_name: null,
    description: "",
    note: "",
    effect,
    resources: resources.map((type) => ({ type })),
    identity: "service" as const,
    max_response_bytes: null,
    vetted_by: "",
    vetted_at: "",
  };
}

const CATALOGUE: ToolGroup[] = [
  {
    origin: "builtin",
    id: "",
    description: "Tools that ship with the platform.",
    tools: [tool("post_message", "write", ["chat.channel"])],
  },
  {
    origin: "connector",
    id: "github-mcp",
    description: "GitHub.",
    tools: [tool("github_mcp_list_issues", "read", ["github.repo"])],
  },
];

/** The **shipped** agent, and the two fields no step here asks about are the point. */
const CONFIG = {
  name: "issue-reporter",
  runtime: "simple",
  system: "You read GitHub issues and summarize them.",
  permissions: {
    tools: ["github_mcp_list_issues", "post_message"],
    scope: {
      "github.repo": { read: ["anthropics/anthropic-sdk-python"] },
      "chat.channel": { write: ["#eng"] },
    },
  },
  default_task: "Summarize the open issues.",
  deny_demo_task: "Summarize torvalds/linux and post to #random.",
};

const AGENT: AgentDetail = {
  name: "issue-reporter",
  runtime: "simple",
  tools: CONFIG.permissions.tools,
  valid: true,
  error: null,
  system: CONFIG.system,
  scope: CONFIG.permissions.scope,
  limits: {},
  updated_at: "2026-08-08T04:12:33.482391+00:00",
  your_role: "owner",
  version: 1,
  config: CONFIG,
};

function show(agent: Partial<AgentDetail> = {}) {
  vi.mocked(api.getAgent).mockResolvedValue({ ...AGENT, ...agent });
  vi.mocked(api.listTools).mockResolvedValue(CATALOGUE);

  // This page reads `/me` from the shell through context, which is not in this tree —
  // supplied here.
  render(
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
      <MemoryRouter initialEntries={["/agents/issue-reporter/edit"]}>
        <Routes>
          <Route path="/agents/:name/edit" element={<EditAgentPage />} />
          <Route path="/agents/:name" element={<div>the agent page</div>} />
        </Routes>
      </MemoryRouter>
    </MeContext.Provider>,
  );
}

beforeEach(() => {
  // The page persists its draft per keystroke since 061, keyed by agent and
  // version — `CreateAgentPage.test`'s rule applies here now too: a draft leaking
  // across tests makes every fixture's config negotiable.
  sessionStorage.clear();
  vi.mocked(api.getAgent).mockReset();
  vi.mocked(api.listTools).mockReset();
  vi.mocked(api.updateAgent).mockReset();
  vi.mocked(api.updateAgent).mockResolvedValue(AGENT);
});

/** Make a real change to the one thing this form still authors. Step 081.
 *
 *  Every test below used to reach for the *Tool calls per run* box, which was the cheapest
 *  lever on the screen. The form no longer offers a ceiling — nothing in this tree reads
 *  one — so the lever is now a scope identifier, which is a `permissions` change and is
 *  therefore also a truer stand-in for what somebody actually opens this page to do. */
const REPO = "anthropics/anthropic-sdk-typescript";

async function changeTheReach(user: ReturnType<typeof userEvent.setup>) {
  const box = await screen.findByLabelText("github.repo 1");
  await user.clear(box);
  await user.type(box, REPO);
  return box;
}

describe("what it loads", () => {
  it("shows every section at once rather than a sequence", async () => {
    show();

    // Editing is not a wizard: somebody arrives to change one thing, so there is nothing
    // to step through and no Continue.
    await screen.findByRole("heading", { name: "Tools" });
    screen.getByRole("heading", { name: "Resources" });
    expect(screen.queryByRole("button", { name: "Continue" })).toBeNull();
    // **And no ceilings and no schema editor since 081.** Both authored config keys
    // nothing in this tree reads, under sentences promising an enforcement that does not
    // happen here — 080 section B, and the reason this screen got shorter.
    expect(screen.queryByRole("heading", { name: "Ceilings" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "May it change anything?" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "The answer it must give" })).toBeNull();
  });

  it("does not let the name be changed", async () => {
    show();

    const field = await screen.findByLabelText(/^ID/);
    expect(field).toBeDisabled();
    expect(field).toHaveValue("issue-reporter");
  });

  it("prefills the identifiers somebody typed when it was created", async () => {
    show();

    await screen.findByRole("heading", { name: "Resources" });
    expect(screen.getByLabelText("github.repo 1")).toHaveValue(
      "anthropics/anthropic-sdk-python",
    );
    expect(screen.getByLabelText("chat.channel 1")).toHaveValue("#eng");
  });

  it("**opens a broken agent, and says what is wrong with it**", async () => {
    // The state `GET /agents/{name}` answered 422 to for four steps, so the one agent
    // somebody needed to fix was the one screen they could not open. Editing is the cure.
    show({ valid: false, error: "agent 'issue-reporter' is granted 'gone_away', which is not a registered tool." });

    // By text rather than by role: this screen has more than one `alert` once it has
    // loaded, and `findByRole` resolves on whichever exists first — which for a moment is
    // the loading state's, not this one.
    const notice = (await screen.findByText(/gone_away/)).closest(".notice")!;
    expect(notice).toHaveTextContent("Fix the configuration below and save");
  });
});

describe("what it saves", () => {
  it("sends only what changed, with the version it was built from", async () => {
    const user = userEvent.setup();
    show();

    await changeTheReach(user);
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(api.updateAgent).toHaveBeenCalled());
    const [name, patch, etag] = vi.mocked(api.updateAgent).mock.calls[0];
    expect(name).toBe("issue-reporter");
    expect(etag).toBe(AGENT.updated_at);
    // **The assertion this screen exists for.** A whole-config save built from this form
    // deletes `system`, `runtime`, `default_task` and `deny_demo_task`, and nothing
    // anywhere would report it. Since 081 that is a property of the shape rather than a
    // guard: `permissions` is the only key `patchFrom` can produce.
    expect(patch).toEqual({
      permissions: {
        tools: CONFIG.permissions.tools,
        scope: {
          "chat.channel": { write: ["#eng"] },
          "github.repo": { read: [REPO] },
        },
      },
    });
  });

  it("cannot be saved until something has changed", async () => {
    show();

    await screen.findByRole("heading", { name: "Resources" });
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
    screen.getByText("No changes yet.");
  });
});

describe("when somebody else got there first", () => {
  function conflict() {
    vi.mocked(api.updateAgent).mockRejectedValue(
      new ApiError(409, "somebody else changed this agent while you were editing it", {
        updated_at: "2026-08-08T05:00:00.000000+00:00",
        changed: ["permissions"],
      }),
    );
  }

  async function saveAnEdit() {
    const user = userEvent.setup();
    await changeTheReach(user);
    await user.click(screen.getByRole("button", { name: "Save changes" }));
    return user;
  }

  it("**says what THEY changed, not just what you were editing**", async () => {
    // The defect this replaced: the server's `changed` is the keys *your* save would
    // write, so a tab editing one field was told about that field — while the scope
    // narrowing it was being protected from went unmentioned.
    // The client holds the version it loaded, so it is the thing that can answer this.
    conflict();
    show();
    // **After `show()`, which sets its own mock.** The re-read has to answer with the
    // version that landed underneath, so this stands in for the other editor's save.
    vi.mocked(api.getAgent).mockResolvedValue({
      ...AGENT,
      config: { ...CONFIG, permissions: { tools: [], scope: {} } },
    });

    await saveAnEdit();

    const theirs = await screen.findByText(/Since you opened this, they changed/);
    expect(within(theirs).getByText("permissions")).toBeTruthy();
  });

  it("and separately what you were about to write", async () => {
    conflict();
    show();

    await saveAnEdit();

    const yours = await screen.findByText(/You were about to change/);
    expect(within(yours).getByText("permissions")).toBeTruthy();
  });

  it("says it once — a 409 does not also render the generic failure", async () => {
    // **Found in a screenshot, not by a test.** Both panels rendered: the generic one
    // repeating the server's sentence, above a panel saying the same thing better. One
    // event, two messages, the less useful one first.
    conflict();
    show();

    await saveAnEdit();
    await screen.findByText("Someone else saved this agent");

    // By the generic panel's own title rather than by counting alerts — `StepTools`
    // legitimately renders one of its own ("this agent will be able to change things"),
    // so a count is a fact about two unrelated things.
    expect(screen.queryByText(/Request failed \(409\)/)).toBeNull();
    expect(
      screen.getAllByText(/somebody else changed this agent|Someone else saved/i),
    ).toHaveLength(1);
  });

  it("offers a reload and **never a save anyway**", async () => {
    conflict();
    show();

    const user = await saveAnEdit();
    await screen.findByRole("button", { name: "Reload" });

    // The whole reason the server refused is that saving anyway is how a scope narrowing
    // gets reverted by somebody who never saw it. There is no override and there must not
    // be one.
    expect(screen.queryByRole("button", { name: /anyway|Force|Overwrite/i })).toBeNull();

    // Asserted through the screen rather than by counting calls: the Conflict panel
    // re-reads the agent itself to work out what they changed, so a call count is now a
    // fact about two things.
    await user.click(screen.getByRole("button", { name: "Reload" }));
    await screen.findByText("No changes yet.");
  });

  it("says plainly when the refused save would have changed nothing", async () => {
    vi.mocked(api.updateAgent).mockRejectedValue(
      new ApiError(409, "somebody else changed this agent", {
        updated_at: "2026-08-08T05:00:00.000000+00:00",
        changed: [],
      }),
    );
    show();

    await saveAnEdit();

    await screen.findByText(/Reloading loses nothing/);
  });
});

/** Step 081. The schema editor is gone, and what it authored is still stored.
 *
 *  It let somebody write a JSON Schema into `output.schema`, refused two mistakes the
 *  server could not word, and warned that an emptied box is not a deletion. All of that
 *  was careful work over a key nothing reads: `agents.check_output` was the completion-time
 *  half of 024's contract and its one caller was `runs.execute`, which this tree does not
 *  have. A control whose sentence promises an enforcement that does not happen is worse
 *  than a missing control, which is 080 section B's whole argument.
 *
 *  What replaces the editor is not silence: the detail page shows the stored schema under
 *  *Stored, and not read here*, so it stays readable — the reader half of 024's register
 *  row, which is the half that was actually asked for. */
describe("the answer schema, after the editor went", () => {
  const SCHEMA = {
    type: "object",
    properties: { summary: { type: "string" } },
    additionalProperties: false,
  };
  const WITH_SCHEMA = { ...CONFIG, output: { schema: SCHEMA } };

  it("offers no way to author one", async () => {
    show({ config: WITH_SCHEMA });

    await screen.findByRole("heading", { name: "Resources" });
    expect(screen.queryByRole("heading", { name: "The answer it must give" })).toBeNull();
    expect(screen.queryByRole("textbox", { name: /schema/i })).toBeNull();
  });

  it("**keeps a stored schema through a save that changed the reach**", async () => {
    // The guarantee, and since 081 it holds by construction rather than by a guard:
    // `patchFrom` can only produce `permissions`, so there is no code path that could
    // send `output` — as a value, as an empty object, or as a null.
    const user = userEvent.setup();
    show({ config: WITH_SCHEMA });

    await changeTheReach(user);
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(api.updateAgent).toHaveBeenCalled());
    const patch = vi.mocked(api.updateAgent).mock.calls[0][1];
    expect(Object.keys(patch as Record<string, unknown>)).toEqual(["permissions"]);
  });

  it("renders a 422 from the server as the server wrote it", async () => {
    // Kept from the editor's own suite, because it is about this page's refusal
    // rendering rather than about schemas: a validator sentence is a string `detail`,
    // `readProblem` passes it through, and it must not arrive through `Failure`'s
    // generic panel. Retitled in 066 — asserting the old sentence would go on passing.
    const user = userEvent.setup();
    vi.mocked(api.updateAgent).mockRejectedValue(
      new ApiError(
        422,
        "agent 'issue-reporter': every object in output.schema must set additionalProperties to false; missing at (root).",
      ),
    );
    show({ config: WITH_SCHEMA });

    await changeTheReach(user);
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    expect(
      await screen.findByText(/every object in output.schema must set additionalProperties/),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("The server would not accept that request"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Changes not saved")).toBeInTheDocument();
    expect(screen.getByText(/Nothing was changed. Fix the problem above and save again/)).toBeInTheDocument();
  });
});

describe("what it says about renaming", () => {
  it("no longer claims a rename changes the grants or the records", async () => {
    show();

    // Grants are keyed by `agent_id` since migration 035 and come with the agent; the
    // logs keep the name that was current when they were written. This paragraph said
    // both of those changed, and `--rename-agent` prints the opposite of the first.
    const said = await screen.findByText(/The owner can rename the agent from its page/);
    expect(said).toHaveTextContent(/Renaming changes the URL/);
    expect(said).toHaveTextContent(/Grants and history are kept/);
    // And it points at the verb rather than denying it exists.
    expect(said).toHaveTextContent(/from its page/);
    expect(screen.queryByText(/It cannot be changed/)).not.toBeInTheDocument();
  });
});

describe("the draft survives (061)", () => {
  // `CreateAgentPage` has persisted every keystroke since the wizard shipped; this
  // page lost twenty minutes of scope decisions to one mis-click. Same mechanism,
  // keyed by agent AND version.
  it("restores an unsaved edit made against this same version", async () => {
    const user = userEvent.setup();
    show();

    await changeTheReach(user);
    cleanup(); // the mis-click: unmounted with nothing saved

    show();
    expect(await screen.findByLabelText("github.repo 1")).toHaveValue(REPO);
    // Restored as an EDIT, not as the truth: Save is live because the draft differs
    // from the stored config, which is what proves `original` stayed the store's.
    expect(screen.getByRole("button", { name: "Save changes" })).toBeEnabled();
  });

  it("never restores a draft made against another version", async () => {
    const user = userEvent.setup();
    show();

    await changeTheReach(user);
    cleanup();

    // Somebody else saved meanwhile: the agent is at version 2 now. Resurrecting the
    // version-1 edit on top of it would be the silent merge the 409 branch refuses.
    show({ version: 2 });
    expect(await screen.findByLabelText("github.repo 1")).toHaveValue(
      "anthropics/anthropic-sdk-python",
    );
  });

  it("a Reload after a 409 shows the new version and keeps no draft under it", async () => {
    // **The 409 path did the merge the 409 path exists to refuse (step 064).**
    // `useResource` keeps the previous `data` while a refetch is in flight, so after
    // Reload the rebuild ran against the STALE version-1 agent, the version-2 answer
    // was then skipped by the old `if (editable) return` guard — so the colleague's
    // save never rendered — and the persist effect wrote the version-1 draft under
    // version 2's key, because it read the version off `agent.data` rather than off
    // whatever the form was actually built from. A later save then sent a
    // version-1-derived patch carrying version 2's `updated_at`, which passes the
    // concurrency check: the silent merge, by the route designed to prevent it.
    const user = userEvent.setup();
    show();

    await changeTheReach(user);

    vi.mocked(api.updateAgent).mockRejectedValueOnce(
      new ApiError(409, "somebody else changed this agent while you were editing it", {
        updated_at: "2026-08-08T05:00:00.000000+00:00",
        changed: ["permissions"],
      }),
    );
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    // The colleague's save is what the refetch will now answer with: they narrowed the
    // repository this agent may read.
    const THEIRS = "anthropics/anthropic-sdk-go";
    const theirConfig = {
      ...CONFIG,
      permissions: {
        ...CONFIG.permissions,
        scope: { ...CONFIG.permissions.scope, "github.repo": { read: [THEIRS] } },
      },
    };
    vi.mocked(api.getAgent).mockResolvedValue({ ...AGENT, version: 2, config: theirConfig });
    await user.click(await screen.findByRole("button", { name: /Reload/ }));

    // Version 2 is on screen — not the stale version-1 build that arrived first.
    await waitFor(() =>
      expect(screen.getByLabelText("github.repo 1")).toHaveValue(THEIRS),
    );
    // And nothing of version 1 is stored under version 2's key, so remounting the
    // page cannot resurrect the edit across somebody else's save.
    cleanup();
    show({ version: 2, config: theirConfig });
    expect(await screen.findByLabelText("github.repo 1")).toHaveValue(THEIRS);
  });

  it("a save clears the draft rather than resurrecting it later", async () => {
    const user = userEvent.setup();
    show();

    await changeTheReach(user);
    await user.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(api.updateAgent).toHaveBeenCalled());
    cleanup();

    show();
    expect(await screen.findByLabelText("github.repo 1")).toHaveValue(
      "anthropics/anthropic-sdk-python",
    );
  });
});
