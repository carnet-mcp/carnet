/** Group management, and the three things it must say out loud.
 *
 * Everything on this screen is one step removed from access — nothing here grants anybody
 * anything — and every mistake it enables is therefore silent. That is what these assert:
 *
 *   - **deleting names the consequence rather than asking "are you sure".** A person
 *     cannot answer the second question. Deleting a group takes its grants with it, on
 *     every agent, immediately, and nobody is told.
 *   - **a no-op is reported.** `PUT` and `DELETE` on a member are both idempotent, so an
 *     administrator who cannot tell "removed" from "was not in it" cannot tell a working
 *     control from a stale screen.
 *   - **membership is fetched per group, when it is opened.** `GET /groups` deliberately
 *     carries no member count because a count is the first step of a company directory,
 *     and a screen that loaded every group's membership to render a list would rebuild
 *     that directory client-side out of ten requests.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return {
    ...actual,
    api: {
      listGroups: vi.fn(),
      getGroup: vi.fn(),
      createGroup: vi.fn(),
      deleteGroup: vi.fn(),
      addMember: vi.fn(),
      removeMember: vi.fn(),
      linkGroup: vi.fn(),
    },
  };
});

import GroupsPage from "./GroupsPage";
import { api, ApiError } from "../../lib/api";
import type { GroupDetail } from "../../lib/types";

const ONCALL = {
  group_id: "g-oncall",
  name: "oncall",
  description: "The rota",
  directory: false,
};

const ENG = {
  group_id: "g-eng",
  name: "eng",
  description: "",
  directory: true,
};

function detail(overrides: Partial<GroupDetail> = {}): GroupDetail {
  return {
    ...ONCALL,
    external_id: null,
    created_by: "user:u_9311",
    members: [
      { kind: "user", id: "u_sam", added_by: "user:u_9311" },
      { kind: "user", id: "u_bala", added_by: "user:u_9311" },
    ],
    ...overrides,
  };
}

function show(groups = [ONCALL]) {
  vi.mocked(api.listGroups).mockResolvedValue(groups);
  return render(
    <MemoryRouter>
      <GroupsPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn === "function" && "mockReset" in fn) vi.mocked(fn).mockReset();
  }
});

describe("the list", () => {
  it("does not fetch anybody's membership until a group is opened", async () => {
    vi.mocked(api.getGroup).mockResolvedValue(detail());
    show();

    expect(await screen.findByText("oncall")).toBeInTheDocument();
    // "Who is in every group" is a map of the company. The list route deliberately cannot
    // answer it, and this screen must not answer it by asking N times.
    expect(api.getGroup).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: "Members" }));

    await waitFor(() => expect(api.getGroup).toHaveBeenCalledWith("g-oncall"));
  });

  it("labels both kinds of group, on the row, without a second request", async () => {
    // **Both, not one.** `ConnectorsPage` marks its exception and stays silent about the
    // norm; here which state is the norm is a property of the deployment, so a single
    // badge would be read as "the exception" and half of all readers would read it
    // backwards.
    const { container } = show([ONCALL, ENG]);

    await screen.findByText("oncall");

    // **Scoped to the row, never to the page.** The create form's own hint ends "Entra
    // emits object ids, Okta names", and `MemberList` says "from your directory" beside a
    // member of a linked group — so a page-wide assertion here would pass on copy that has
    // nothing to do with these labels. 035g paid for that lesson in a DOM test.
    const rows = [...container.querySelectorAll(".row")];
    const byName = (name: string) =>
      rows.find((row) => row.textContent?.includes(name))!;

    expect(byName("oncall")).toHaveTextContent("managed here");
    expect(byName("oncall")).toHaveTextContent("An administrator adds and removes members");
    expect(byName("oncall")).not.toHaveTextContent("from your directory");

    expect(byName("eng")).toHaveTextContent("from your directory");
    expect(byName("eng")).toHaveTextContent("Membership comes from your directory");
    expect(byName("eng")).not.toHaveTextContent("managed here");

    // The boolean rides on the listing. A badge that cost one request per group would be
    // the company directory rebuilt client-side — the thing `GroupSummary` refuses to be.
    expect(api.listGroups).toHaveBeenCalledTimes(1);
    expect(api.getGroup).not.toHaveBeenCalled();
  });

  it("keeps the row label distinct from the member-level one when the group is open", async () => {
    // Opening a directory-backed group puts *"from your directory"* on screen twice: once
    // as this chunk's row label, and once per member as the reason there is no Remove
    // button. They mean different things — where the membership comes from, and why this
    // person cannot be taken out — and a page-wide assertion cannot tell them apart.
    vi.mocked(api.getGroup).mockResolvedValue(
      detail({ ...ENG, external_id: "dir-eng-8f2c" }),
    );
    const { container } = show([ENG]);

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));
    await screen.findByText(/Membership follows the directory group/);

    const row = container.querySelector(".row")!;
    // The row label is outside the nested panel, which is what makes it a property of the
    // group rather than of anybody in it.
    const nested = row.querySelector(".nested")!;
    const label = [...row.querySelectorAll(".tag")].map((t) => t.textContent);
    expect(label).toEqual(["from your directory"]);
    expect(nested.querySelectorAll(".tag")).toHaveLength(0);
    // And the member-level sentence is still there, saying its own thing.
    expect(nested.textContent).toContain("from your directory");
  });

  it("says an empty group has no members", async () => {
    vi.mocked(api.getGroup).mockResolvedValue(detail({ members: [] }));
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));

    // The mistake this prevents: sharing an agent with an empty group and believing a
    // team now has access. The page says the group is empty rather than rendering
    // an empty table.
    expect(await screen.findByText(/No members yet/)).toBeInTheDocument();
  });
});

describe("creating", () => {
  it("renders a duplicate name as the server's own sentence", async () => {
    vi.mocked(api.createGroup).mockRejectedValue(
      new ApiError(
        400,
        "tenant 't-acme' already has a group called 'oncall'. Names are how a person " +
          "picks a group on the command line, so two with one name is a command whose " +
          "meaning depends on insertion order.",
      ),
    );
    show();

    await userEvent.type(await screen.findByLabelText(/^Name/), "oncall");
    await userEvent.click(screen.getByRole("button", { name: "Create group" }));

    expect(await screen.findByText(/depends on insertion order/)).toBeInTheDocument();
  });

  it("says why the button is unavailable rather than only disabling it", async () => {
    show();

    expect(await screen.findByText("Enter a name.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create group" })).toBeDisabled();
  });
});

describe("membership", () => {
  it("says when removing somebody did nothing", async () => {
    vi.mocked(api.getGroup).mockResolvedValue(detail());
    vi.mocked(api.removeMember).mockResolvedValue({
      group_id: "g-oncall",
      kind: "user",
      id: "u_sam",
      changed: false,
    });
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));
    const [remove] = await screen.findAllByRole("button", { name: "Remove" });
    await userEvent.click(remove);

    expect(await screen.findByText("user:u_sam was not in this group.")).toBeInTheDocument();
  });

  it("says what removing somebody costs them, before anybody presses it", async () => {
    vi.mocked(api.getGroup).mockResolvedValue(detail());
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));

    expect(
      await screen.findByText(/ends their access through this group on every agent/),
    ).toBeInTheDocument();
  });

  it("takes a member by user id, the form the audit log shows", async () => {
    vi.mocked(api.getGroup).mockResolvedValue(detail());
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));

    // By id and not by email, and that is a limit rather than a preference: a route
    // resolving an address to a principal would be an enumeration oracle over the
    // company directory. The screen says which id it wants and where to read it from.
    expect(await screen.findByText(/The user ID, as shown in the audit log/)).toBeInTheDocument();
  });

  it("reports a member who was already in the group", async () => {
    vi.mocked(api.getGroup).mockResolvedValue(detail());
    vi.mocked(api.addMember).mockResolvedValue({
      group_id: "g-oncall",
      kind: "user",
      id: "u_sam",
      changed: false,
    });
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));
    await userEvent.type(
      await screen.findByPlaceholderText("u_9311cad7b95c4592"),
      "u_sam",
    );
    await userEvent.click(screen.getByRole("button", { name: "Add" }));

    expect(await screen.findByText("user:u_sam was already in this group.")).toBeInTheDocument();
  });
});

describe("deleting", () => {
  it("names the consequence and the member count, rather than asking twice", async () => {
    vi.mocked(api.getGroup).mockResolvedValue(detail());
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));
    await userEvent.click(await screen.findByRole("button", { name: "Delete group" }));

    // "Are you sure" asks a question a person cannot answer. This one they can.
    const warning = await screen.findByText(/lose access to every agent shared with this group/);
    expect(warning).toHaveTextContent("All 2 members");
    expect(warning).toHaveTextContent("immediately");
    expect(warning).toHaveTextContent("cannot be undone");
  });

  it("keeps the group visible while the decision is being made", async () => {
    vi.mocked(api.getGroup).mockResolvedValue(detail());
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));
    await userEvent.click(await screen.findByRole("button", { name: "Delete group" }));

    // In place rather than in a modal: the thing being deleted, and who is in it, stay on
    // screen while somebody decides.
    expect(screen.getByText("user:u_sam")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeInTheDocument();
  });

  it("gets the singular right for a group of one", async () => {
    vi.mocked(api.getGroup).mockResolvedValue(
      detail({ members: [{ kind: "user", id: "u_sam", added_by: "" }] }),
    );
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));
    await userEvent.click(await screen.findByRole("button", { name: "Delete group" }));

    expect(await screen.findByText(/All 1 member lose/)).toBeInTheDocument();
  });

  it("does not delete until the second button is pressed", async () => {
    vi.mocked(api.getGroup).mockResolvedValue(detail());
    vi.mocked(api.deleteGroup).mockResolvedValue(undefined);
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));
    await userEvent.click(await screen.findByRole("button", { name: "Delete group" }));
    expect(api.deleteGroup).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(api.deleteGroup).toHaveBeenCalledWith("g-oncall"));
  });
});

/** Step 033e. A directory-backed group is one whose membership is not this screen's to
 *  edit, and every control that pretends otherwise is a control the server refuses. */
describe("following a directory", () => {
  it("names what linking costs the people who are in it now", async () => {
    vi.mocked(api.getGroup).mockResolvedValue(detail());
    vi.mocked(api.linkGroup).mockResolvedValue(detail({ external_id: "dir-oncall" }));
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));
    await userEvent.type(await screen.findByPlaceholderText("Directory group id"), "dir-oncall");

    // The consequence, before it happens — the count stops being knowable once the
    // directory starts applying itself one sign-in at a time.
    expect(
      await screen.findByText(/2 people are in it now/),
    ).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Link" }));

    await waitFor(() =>
      expect(api.linkGroup).toHaveBeenCalledWith("g-oncall", "dir-oncall"),
    );
  });

  it("offers no way to add or remove a person once it follows one", async () => {
    vi.mocked(api.getGroup).mockResolvedValue(detail({ external_id: "dir-oncall" }));
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));

    // Not a disabled button: a control that exists and does nothing reads as a bug,
    // which is the same reasoning the share sheet's inherited rows already carry.
    expect(await screen.findAllByText("from your directory")).toHaveLength(2);
    expect(screen.queryByRole("option", { name: "user" })).not.toBeInTheDocument();
    expect(screen.getByRole("option", { name: "system" })).toBeInTheDocument();
  });

  it("says the list is only the people who have signed in since", async () => {
    vi.mocked(api.getGroup).mockResolvedValue(detail({ external_id: "dir-oncall" }));
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));

    expect(
      await screen.findByText(/listed after their next sign-in/),
    ).toBeInTheDocument();
  });

  it("stops offering to add a person the moment the group follows one", async () => {
    // `kind` is `useState`-initialised from the link state and a reload does not
    // unmount the form, so after linking the select still said `user` and offered an
    // Add the server refuses — the control-that-reads-as-broken this screen argues
    // against everywhere else.
    vi.mocked(api.getGroup)
      .mockResolvedValueOnce(detail())
      .mockResolvedValue(detail({ external_id: "dir-oncall" }));
    vi.mocked(api.linkGroup).mockResolvedValue(detail({ external_id: "dir-oncall" }));
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));
    expect(await screen.findByRole("option", { name: "user" })).toBeInTheDocument();

    await userEvent.type(
      screen.getByPlaceholderText("Directory group id"),
      "dir-oncall",
    );
    await userEvent.click(screen.getByRole("button", { name: "Link" }));

    await waitFor(() =>
      expect(screen.queryByRole("option", { name: "user" })).not.toBeInTheDocument(),
    );
  });

  it("does not claim a scheduler signed in", async () => {
    // §7 permits `system` members in a linked group — the directory never writes those
    // rows — so the sentence about who has signed in is false about every row here.
    vi.mocked(api.getGroup).mockResolvedValue(
      detail({
        external_id: "dir-oncall",
        members: [{ kind: "system", id: "nightly", added_by: "user:u_9311" }],
      }),
    );
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));
    await screen.findByText(/nightly/);

    expect(screen.queryByText(/listed after their next sign-in/)).not.toBeInTheDocument();
  });

  it("unlinks without removing anybody, and says so", async () => {
    vi.mocked(api.getGroup).mockResolvedValue(detail({ external_id: "dir-oncall" }));
    vi.mocked(api.linkGroup).mockResolvedValue(detail());
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Members" }));
    expect(await screen.findByText(/Nobody is removed/)).toBeInTheDocument();

    await userEvent.click(
      screen.getByRole("button", { name: "Stop following the directory" }),
    );

    await waitFor(() => expect(api.linkGroup).toHaveBeenCalledWith("g-oncall", null));
  });
});
