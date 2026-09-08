/** The share sheet, and the two distinctions it exists to make visible.
 *
 * **Inherited access is not a row you can remove**, and **a share to an address that has
 * never signed in grants nobody anything.** Both are states this system has had since 9a
 * and 006 respectively, and both look identical to real access on a screen that does not
 * say so — which is the whole failure mode: somebody revokes a grant, watches the agent
 * stay visible through a group, and concludes the revoke failed.
 */

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return {
    ...actual,
    api: {
      agentAccess: vi.fn(),
      shareAgent: vi.fn(),
      unshareAgent: vi.fn(),
      listGroups: vi.fn(),
      myTokens: vi.fn(),
    },
  };
});

import ShareSheet from "./ShareSheet";
import { api, ApiError } from "../../lib/api";
import type {
  AgentAccess,
  AgentDetail,
  GroupSummary,
  OwnedToken,
} from "../../lib/types";

const AGENT: AgentDetail = {
  name: "minimal",
  runtime: "simple",
  tools: [],
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

/** The real shape of `who_has_access`: a direct owner, a group, and somebody who reaches
 *  the agent **only** through that group and has no grant row anywhere. */
const SHEET: AgentAccess = {
  access: [
    {
      kind: "group",
      id: "g_6f5b",
      role: "user",
      direct: "user",
      via: [],
      granted_by: "user:u_priya",
      directory: false,
    },
    {
      kind: "user",
      id: "u_bala",
      role: "user",
      direct: null,
      via: ["g_6f5b"],
      granted_by: "",
      directory: false,
    },
    {
      kind: "user",
      id: "u_priya",
      role: "owner",
      direct: "owner",
      via: [],
      granted_by: "user:u_priya",
      directory: false,
    },
  ],
  waiting: [{ email: "newhire@acme.com", role: "user", granted_by: "user:u_priya" }],
};

/** The tenant's groups, as `GET /groups` answers them: the boolean and no `external_id`.
 *  One of each kind, because 035h's decision is that **both** are labelled. */
const GROUPS: GroupSummary[] = [
  { group_id: "g_6f5b", name: "oncall", description: "The rota", directory: false },
  { group_id: "g_dir", name: "eng", description: "", directory: true },
];

/** Three tokens covering the picker's whole branch: one grantable service token, one
 *  personal (never offered — it holds no grants of its own), one revoked. */
const TOKENS: OwnedToken[] = [
  {
    id: "m_svc",
    name: "support-bot",
    owner_id: "u_1",
    acts_as_owner: false,
    created_by: "u_1",
    created_at: "2026-08-01T00:00:00Z",
    expires_at: null,
    revoked_at: null,
    revoked_by: null,
    last_used_at: null,
  },
  {
    id: "m_own",
    name: "my-laptop",
    owner_id: "u_1",
    acts_as_owner: true,
    created_by: "u_1",
    created_at: "2026-08-01T00:00:00Z",
    expires_at: null,
    revoked_at: null,
    revoked_by: null,
    last_used_at: null,
  },
  {
    id: "m_dead",
    name: "old-bot",
    owner_id: "u_1",
    acts_as_owner: false,
    created_by: "u_1",
    created_at: "2026-08-01T00:00:00Z",
    expires_at: null,
    revoked_at: "2026-08-20T00:00:00Z",
    revoked_by: "u_1",
    last_used_at: null,
  },
];

function show(
  sheet: Partial<AgentAccess> = {},
  agent: Partial<AgentDetail> = {},
  groups: GroupSummary[] = GROUPS,
  tokens: OwnedToken[] = TOKENS,
) {
  vi.mocked(api.agentAccess).mockResolvedValue({ ...SHEET, ...sheet });
  vi.mocked(api.listGroups).mockResolvedValue(groups);
  vi.mocked(api.myTokens).mockResolvedValue(tokens);
  render(<ShareSheet agent={{ ...AGENT, ...agent }} />);
}

/** Switch the grantee chooser to groups. One control, not a second Share button — so
 *  every group assertion below starts by picking the kind, exactly as a person does. */
async function chooseGroups(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("radio", { name: /A group/ }));
}

/** Switch the grantee chooser to tokens, for the same reason `chooseGroups` exists. */
async function chooseTokens(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("radio", { name: /A token/ }));
}

/** The row for one grantee, matched on its **first cell** rather than anywhere in the
 *  row.
 *
 *  A group id appears twice on this screen by design — once as the grantee and once in
 *  the "through g_6f5b" of everybody who inherits from it — so a search over the whole
 *  row is ambiguous by construction. That duplication is the feature. */
async function row(id: string): Promise<HTMLElement> {
  await screen.findAllByRole("row");
  const found = Array.from(document.querySelectorAll("tr")).find((tr) =>
    tr.querySelector("td")?.textContent?.includes(id),
  );
  if (!found) throw new Error(`no row for ${id}`);
  return found as HTMLElement;
}

beforeEach(() => {
  vi.mocked(api.agentAccess).mockReset();
  vi.mocked(api.shareAgent).mockReset();
  vi.mocked(api.unshareAgent).mockReset();
  vi.mocked(api.listGroups).mockReset();
  vi.mocked(api.myTokens).mockReset();
  vi.mocked(api.unshareAgent).mockResolvedValue(undefined);
  vi.mocked(api.listGroups).mockResolvedValue(GROUPS);
  vi.mocked(api.myTokens).mockResolvedValue(TOKENS);
});

describe("how somebody has access", () => {
  it("**says which group inherited access comes through**", async () => {
    show();

    expect(await row("u_bala")).toHaveTextContent("through g_6f5b");
  });

  it("offers no Remove on access nobody can remove from here", async () => {
    // Deliberately not a disabled button. A control that exists and does nothing reads
    // as a bug; a sentence saying where the access comes from is the thing that gets
    // acted on — which is what `unshare` refuses with, one layer down.
    show();

    const inherited = await row("u_bala");
    expect(within(inherited).queryByRole("button")).toBeNull();
    expect(inherited).toHaveTextContent("remove them from the group");
  });

  it("offers no Remove on the owner, and says so", async () => {
    show();

    const owner = await row("u_priya");
    expect(within(owner).queryByRole("button")).toBeNull();
    expect(owner).toHaveTextContent("owns it");
  });

  it("lets a group's own grant be removed, which is one of the two things that work", async () => {
    const user = userEvent.setup();
    show();

    const group = await row("g_6f5b");
    await user.click(within(group).getByRole("button", { name: "Remove" }));
    // 061: the two-step every other destructive control already had. The first
    // click removes nothing; the confirm carries the group-shaped consequence.
    expect(api.unshareAgent).not.toHaveBeenCalled();
    expect(group).toHaveTextContent(/Everybody reaching it through this group/);
    await user.click(within(group).getByRole("button", { name: "Remove it" }));

    expect(api.unshareAgent).toHaveBeenCalledWith("minimal", "group", "g_6f5b");
  });

  it("keeping it removes nothing and puts the Remove back", async () => {
    const user = userEvent.setup();
    show();

    const group = await row("g_6f5b");
    await user.click(within(group).getByRole("button", { name: "Remove" }));
    await user.click(within(group).getByRole("button", { name: "Keep" }));

    expect(api.unshareAgent).not.toHaveBeenCalled();
    expect(
      within(group).getByRole("button", { name: "Remove" }),
    ).toBeInTheDocument();
  });

  it("renders the server's refusal when a revoke would have changed nothing", async () => {
    const user = userEvent.setup();
    vi.mocked(api.unshareAgent).mockRejectedValue(
      new ApiError(
        400,
        "'u_bala' has no grant of their own on 'minimal' — their access comes from group:g_6f5b.",
        {},
      ),
    );
    show({
      access: [
        {
          kind: "user",
          id: "u_sam",
          role: "user",
          direct: "user",
          via: [],
          granted_by: "",
          directory: false,
        },
      ],
    });

    const sam = await row("u_sam");
    await user.click(within(sam).getByRole("button", { name: "Remove" }));
    await user.click(within(sam).getByRole("button", { name: "Remove it" }));

    await screen.findByText(/their access comes from/);
    screen.getByText(/Nothing was changed/);
  });
});

describe("who is waiting", () => {
  it("keeps pending addresses out of the list of people who can reach it", async () => {
    // Merging them would report access that does not exist. Nobody has this yet.
    show();

    await screen.findByRole("heading", { name: "Waiting for a first sign-in" });
    const listed = await screen.findByText("newhire@acme.com");
    expect(listed.closest("table")).not.toBe((await row("u_priya")).closest("table"));
  });

  it("says nothing about waiting when nobody is", async () => {
    show({ waiting: [] });

    await screen.findByText("u_priya");
    expect(screen.queryByRole("heading", { name: "Waiting for a first sign-in" })).toBeNull();
  });
});

describe("sharing", () => {
  it("**reports which of the two things happened**", async () => {
    // 006 made this invisible to the sharer by design. The two look identical on a
    // screen and only one of them means anybody actually has access.
    const user = userEvent.setup();
    vi.mocked(api.shareAgent).mockResolvedValue({
      outcome: "pending",
      kind: "email",
      id: "newhire@acme.com",
      role: "user",
    });
    show();

    await user.type(
      await screen.findByLabelText(/Email address/),
      "newhire@acme.com",
    );
    await user.click(screen.getByRole("button", { name: "Share" }));

    await screen.findByText("Nobody has this access yet");
    expect(api.shareAgent).toHaveBeenCalledWith(
      "minimal", "email", "newhire@acme.com", "user",
    );
  });

  it("says so plainly when the share landed", async () => {
    const user = userEvent.setup();
    vi.mocked(api.shareAgent).mockResolvedValue({
      outcome: "granted",
      kind: "email",
      id: "sam@acme.com",
      role: "user",
    });
    show();

    await user.type(await screen.findByLabelText(/Email address/), "sam@acme.com");
    await user.click(screen.getByRole("button", { name: "Share" }));

    await screen.findByText("Shared");
    await waitFor(() => expect(api.agentAccess).toHaveBeenCalledTimes(2));
  });

  it("offers no ownership transfer from here", async () => {
    // Granting `owner` is a **transfer** — the server demotes whoever holds it now — and
    // a thing that changes two people's access at once does not belong in the same
    // control as "share this with Sam".
    show();

    await screen.findByLabelText(/Email address/);
    // Scoped to the level chooser by its `name`. 035h put a second radio group on this
    // form — who, then what — and a bare `getAllByRole("radio")` would now be asserting
    // about both, which is the page-wide assertion mistake one control smaller.
    const levels = screen
      .getAllByRole("radio")
      .filter((input) => (input as HTMLInputElement).name === "share-role")
      .map((input) => input.closest("label")!.textContent);
    expect(levels).toEqual(["Can run it — run it, and see what it may reach",
                            "Can change it — …and edit it, and share it on"]);
  });

  it("labels a machine grantee as a token rather than as another person", async () => {
    // Step 020. An opaque `m_...` beside a `u_...` reads as another colleague, and the
    // one question this screen answers is who can reach the agent. The union in
    // `types.ts` was hand-written from `schemas.py` and went stale the moment a fourth
    // kind existed — plan 010 predicted that drift for this exact file.
    show({
      access: [
        ...SHEET.access,
        {
          kind: "machine",
          id: "m_4ceece1001b54da8",
          role: "user",
          direct: "user",
          via: [],
          granted_by: "system:cli",
          directory: false,
        },
      ],
    });

    await screen.findByText("token m_4ceece1001b54da8");
    screen.getByText("an API token, acting unattended");
  });

  it("shows a reader the sheet and not the controls", async () => {
    // `GET .../access` is readable at `user` on purpose: somebody about to run an agent
    // that acts on their data should see who else can reach it. Changing it is `editor`.
    show({}, { your_role: "user" });

    await screen.findByText("u_priya");
    expect(screen.queryByLabelText(/Email address/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Remove" })).toBeNull();
    screen.getByText(/Changing it needs the level above yours/);
    // And makes no request for a tenant-wide group listing. `GET /groups` is open to
    // everybody authenticated, which is a reason to fetch it where it is used rather than
    // a reason not to care: a reader of this sheet has not asked what teams exist.
    expect(api.listGroups).not.toHaveBeenCalled();
  });
});

/** Step 035h. The half of this screen its own docstring described since 12b and did
 *  not have: `ShareBox` passed `email` as the grantee kind literally, so an agent could be
 *  shared with a group from the CLI and from nowhere in the product. */
describe("sharing with a group", () => {
  it("**shares with the group the route has accepted since 9a**", async () => {
    const user = userEvent.setup();
    vi.mocked(api.shareAgent).mockResolvedValue({
      outcome: "granted",
      kind: "group",
      id: "g_dir",
      role: "user",
    });
    show();
    await chooseGroups(user);

    await user.selectOptions(await screen.findByLabelText(/^Group/), "g_dir");
    await user.click(screen.getByRole("button", { name: "Share" }));

    expect(api.shareAgent).toHaveBeenCalledWith("minimal", "group", "g_dir", "user");
    // The sheet reloads, because the group is now a row in it with its own Remove.
    await waitFor(() => expect(api.agentAccess).toHaveBeenCalledTimes(2));
  });

  it("labels both kinds of group rather than marking one", async () => {
    const user = userEvent.setup();
    show();
    await chooseGroups(user);

    const options = within(await screen.findByLabelText(/^Group/))
      .getAllByRole("option")
      .map((option) => option.textContent);

    expect(options).toEqual([
      "Choose a group…",
      "oncall — whoever an administrator puts in it",
      "eng — whoever your directory puts in it",
    ]);
  });

  it("says what a directory-backed group costs before the share, not after", async () => {
    const user = userEvent.setup();
    show();
    await chooseGroups(user);

    await user.selectOptions(await screen.findByLabelText(/^Group/), "g_dir");

    // The one case where "who will this reach" has no answer this screen can give.
    screen.getByText(/including people who have never signed in here/);
    expect(screen.queryByText(/managed by an administrator/)).toBeNull();

    await user.selectOptions(screen.getByLabelText(/^Group/), "g_6f5b");
    screen.getByText(/managed by an administrator/);
    expect(screen.queryByText(/never signed in here/)).toBeNull();
  });

  it("renders an empty list as the sentence it is, and names who makes one", async () => {
    const user = userEvent.setup();
    show({}, {}, []);
    await chooseGroups(user);

    // Making a group is `POST /groups`, administrator surface. A create control here is
    // how somebody invents a group to solve a share and leaves an unmanaged one behind.
    await screen.findByText(/There are no groups in this workspace yet/);
    expect(screen.queryByRole("combobox")).toBeNull();
    expect(screen.getByRole("button", { name: "Share" })).toBeDisabled();
  });

  it("renders the server's sentence when the group went away since the list loaded", async () => {
    // A picker's list is stale the moment it renders. `grant_agent`'s contract says both
    // stores refuse a group nobody created with the same sentence, because a grant naming
    // one is a row that grants nothing and looks exactly like access.
    const user = userEvent.setup();
    vi.mocked(api.shareAgent).mockRejectedValue(
      new ApiError(
        400,
        "tenant 't-acme' has no group 'g_dir'. A grant naming a group nobody created is " +
          "a row that grants nothing and looks exactly like access.",
        {},
      ),
    );
    show();
    await chooseGroups(user);

    await user.selectOptions(await screen.findByLabelText(/^Group/), "g_dir");
    await user.click(screen.getByRole("button", { name: "Share" }));

    await screen.findByText(/looks exactly like access/);
  });

  it("renders the server's failure instead of an empty picker when the menu will not load", async () => {
    // The distinction that matters: *there are no groups* and *we could not ask* are
    // different facts, and the empty-state sentence would report the second as the
    // first — telling somebody to go and make a group that may already exist.
    const user = userEvent.setup();
    vi.mocked(api.agentAccess).mockResolvedValue(SHEET);
    vi.mocked(api.listGroups).mockRejectedValue(
      new ApiError(503, "storage unavailable: try again later", {}),
    );
    render(<ShareSheet agent={AGENT} />);
    await chooseGroups(user);

    await screen.findByText(/storage unavailable/);
    expect(screen.queryByText(/There are no groups in this workspace yet/)).toBeNull();
    expect(screen.getByRole("button", { name: "Share" })).toBeDisabled();
  });

  it("keeps the level when the kind changes, because they are two questions", async () => {
    const user = userEvent.setup();
    vi.mocked(api.shareAgent).mockResolvedValue({
      outcome: "granted", kind: "group", id: "g_dir", role: "editor",
    });
    show();

    await user.click(await screen.findByRole("radio", { name: /Can change it/ }));
    await chooseGroups(user);
    await user.selectOptions(await screen.findByLabelText(/^Group/), "g_dir");
    await user.click(screen.getByRole("button", { name: "Share" }));

    // A form that quietly reset the level on a kind change would share at `user` while
    // the screen said `editor` — the class of bug where the screen and the request
    // disagree and only the audit log knows.
    expect(api.shareAgent).toHaveBeenCalledWith("minimal", "group", "g_dir", "editor");
  });

  it("still offers a group the agent is already shared with", async () => {
    // Re-sharing is an upsert that changes the level, which is what a `PUT` keyed by
    // grantee means. Filtering the list against the table above would remove the only
    // way to change a group's role from this screen.
    const user = userEvent.setup();
    show();
    await chooseGroups(user);

    const options = within(await screen.findByLabelText(/^Group/))
      .getAllByRole("option")
      .map((option) => (option as HTMLOptionElement).value);

    // `g_6f5b` is the group already on the sheet, with its own Remove button.
    expect(options).toContain("g_6f5b");
  });

  it("renders a hostile group name as text", async () => {
    const user = userEvent.setup();
    show({}, {}, [
      { group_id: "g_x", name: "<img src=x onerror=alert(1)>", description: "",
        directory: false },
    ]);
    await chooseGroups(user);

    const picker = await screen.findByLabelText(/^Group/);
    expect(within(picker).getAllByRole("option")[1]).toHaveTextContent(
      "<img src=x onerror=alert(1)> — whoever an administrator puts in it",
    );
    expect(picker.querySelector("img")).toBeNull();
  });

  it("clears a refusal when the kind changes, so it is not read against the new one", async () => {
    const user = userEvent.setup();
    vi.mocked(api.shareAgent).mockRejectedValue(
      new ApiError(400, "tenant 't-acme' has no group 'g_dir'.", {}),
    );
    show();
    await chooseGroups(user);
    await user.selectOptions(await screen.findByLabelText(/^Group/), "g_dir");
    await user.click(screen.getByRole("button", { name: "Share" }));
    await screen.findByText(/has no group/);

    await user.click(screen.getByRole("radio", { name: /A person/ }));

    // A refusal about a group, left standing over an email field, reads as a refusal
    // about the address somebody is about to type.
    expect(screen.queryByText(/has no group/)).toBeNull();
  });

  it("fetches the groups once and does not poll", async () => {
    const user = userEvent.setup();
    show();
    await chooseGroups(user);

    await screen.findByLabelText(/^Group/);
    await waitFor(() => expect(api.listGroups).toHaveBeenCalledTimes(1));
    // Long enough that a two-second poll would have fired.
    await new Promise((resolve) => setTimeout(resolve, 2100));
    expect(api.listGroups).toHaveBeenCalledTimes(1);
  });
});

/** Step 065. The verb that makes a minted token do anything, which until now existed
 *  only at a terminal — the route has always taken `machine`. */
describe("sharing with a token", () => {
  it("**grants the agent to the chosen token, at `user`**", async () => {
    const user = userEvent.setup();
    vi.mocked(api.shareAgent).mockResolvedValue({
      outcome: "granted",
      kind: "machine",
      id: "m_svc",
      role: "user",
    });
    show();
    await chooseTokens(user);

    await user.selectOptions(await screen.findByLabelText(/^Token/), "m_svc");
    await user.click(screen.getByRole("button", { name: "Share" }));

    await waitFor(() =>
      expect(api.shareAgent).toHaveBeenCalledWith("minimal", "machine", "m_svc", "user"),
    );
  });

  it("**never offers a personal token** — it holds no grants of its own", async () => {
    const user = userEvent.setup();
    show();
    await chooseTokens(user);

    const picker = await screen.findByLabelText(/^Token/);
    expect(within(picker).getByRole("option", { name: /support-bot/ })).toBeTruthy();
    expect(within(picker).queryByRole("option", { name: /my-laptop/ })).toBeNull();
  });

  it("never offers a revoked token", async () => {
    const user = userEvent.setup();
    show();
    await chooseTokens(user);

    const picker = await screen.findByLabelText(/^Token/);
    expect(within(picker).queryByRole("option", { name: /old-bot/ })).toBeNull();
  });

  it("**says why the picker is empty** when every live token is a personal one", async () => {
    const user = userEvent.setup();
    show({}, {}, GROUPS, [TOKENS[1]]);
    await chooseTokens(user);

    expect(await screen.findByText(/all personal ones/)).toBeTruthy();
    expect(screen.queryByLabelText(/^Token/)).toBeNull();
  });

  it("names the tokens page when there are no tokens at all", async () => {
    const user = userEvent.setup();
    show({}, {}, GROUPS, []);
    await chooseTokens(user);

    expect(await screen.findByText(/no service tokens/)).toBeTruthy();
  });

  it("**offers no level for a token** — a program does not edit what bounds it", async () => {
    const user = userEvent.setup();
    show();
    await chooseTokens(user);

    await screen.findByLabelText(/^Token/);
    expect(screen.queryByRole("radio", { name: /Can change it/ })).toBeNull();
    expect(screen.getByText(/does not edit the list that bounds it/)).toBeTruthy();
  });

  it("**confirms in terms of what the assistant does next**, since nothing is sent", async () => {
    const user = userEvent.setup();
    vi.mocked(api.shareAgent).mockResolvedValue({
      outcome: "granted",
      kind: "machine",
      id: "m_svc",
      role: "user",
    });
    show();
    await chooseTokens(user);

    await user.selectOptions(await screen.findByLabelText(/^Token/), "m_svc");
    await user.click(screen.getByRole("button", { name: "Share" }));

    const notice = await screen.findByText(/appear in its next/);
    expect(notice.textContent).toContain("support-bot");
    expect(notice.textContent).toContain("shown once");
  });

  it("renders a refusal from the route rather than reporting success", async () => {
    const user = userEvent.setup();
    vi.mocked(api.shareAgent).mockRejectedValue(
      new ApiError(400, "that token has been revoked", {}),
    );
    show();
    await chooseTokens(user);

    await user.selectOptions(await screen.findByLabelText(/^Token/), "m_svc");
    await user.click(screen.getByRole("button", { name: "Share" }));

    expect(await screen.findByText(/has been revoked/)).toBeTruthy();
  });
});
