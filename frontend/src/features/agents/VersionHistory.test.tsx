/** The history card, and the two things it exists to say.
 *
 * **Which version is running now**, because a list of eight configurations with nothing
 * marking the live one is a list somebody has to work out by date. And **which of them
 * can no longer be restored**, which is a fact about today rather than about the version:
 * a tool un-vetted last week makes a version from last month unrestorable without
 * anything having touched the row, so the card has to say so before the click rather
 * than letting the restore answer 422 after it.
 */

import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return { ...actual, api: { agentVersions: vi.fn() } };
});

import VersionHistory, { describeAuthor } from "./VersionHistory";
import { api } from "../../lib/api";
import type { AgentDetail, AgentVersionSummary } from "../../lib/types";

const AGENT: AgentDetail = {
  name: "minimal",
  runtime: "simple",
  tools: [],
  valid: true,
  error: null,
  system: "",
  scope: {},
  limits: {},
  updated_at: "2026-08-13T04:12:33.482391+00:00",
  your_role: "owner",
  version: 3,
  config: {},
};

function version(overrides: Partial<AgentVersionSummary> = {}): AgentVersionSummary {
  return {
    version: 1,
    created_at: "2026-08-01T04:12:33.482391+00:00",
    created_by: "user:u_9311cad7",
    source: "update",
    restored_from: null,
    valid: true,
    error: null,
    ...overrides,
  };
}

function show(history: AgentVersionSummary[], agent: Partial<AgentDetail> = {}) {
  vi.mocked(api.agentVersions).mockResolvedValue(history);
  render(
    <MemoryRouter>
      <VersionHistory agent={{ ...AGENT, ...agent }} />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(api.agentVersions).mockReset();
});

describe("what the card says about each version", () => {
  it("marks the one that is running now, and only that one", async () => {
    show([version({ version: 3 }), version({ version: 2 }), version({ version: 1 })]);

    const live = await screen.findByText("live");
    const row = live.closest("tr");
    expect(within(row!).getByRole("link")).toHaveTextContent("v3");
    expect(screen.getAllByText("live")).toHaveLength(1);
  });

  it("says a version cannot be restored, rather than leaving it to the click", async () => {
    show([
      version({ version: 3 }),
      version({
        version: 2,
        valid: false,
        error: "agent 'minimal' is granted 'notes_read_page', which is not a registered tool",
      }),
      version({ version: 1 }),
    ]);

    const warned = await screen.findByText("cannot be restored");
    expect(within(warned.closest("tr")!).getByRole("link")).toHaveTextContent("v2");
    // The validator's own sentence, carried rather than paraphrased — it is what the
    // restore would answer with, and two wordings for one refusal is the drift.
    expect(warned).toHaveAttribute("title", expect.stringContaining("notes_read_page"));
  });

  it("says where a restored version came from", async () => {
    show([version({ version: 3, source: "restore", restored_from: 1 })]);

    expect(await screen.findByText("restored from v1")).toBeInTheDocument();
  });

  it("links each version to its own page, because a URL is what somebody sends", async () => {
    show([version({ version: 3 }), version({ version: 2 })]);

    const link = await screen.findByRole("link", { name: "v2" });
    expect(link).toHaveAttribute("href", "/agents/minimal/versions/2");
  });

  it("counts the versions there are, not the rows it was sent", async () => {
    // **The server caps this list.** Counting rows said "50 versions" about an agent
    // that had sixty — a card that miscounts the thing it is a card about. Found by
    // driving the route with 55 edits in the edge hunt.
    show(
      Array.from({ length: 50 }, (_, i) => version({ version: 60 - i })),
      { version: 60 },
    );

    expect(await screen.findByText("50 most recent of 60")).toBeInTheDocument();
  });

  it("says the plain count when it is showing all of them", async () => {
    show([version({ version: 3 }), version({ version: 2 }), version({ version: 1 })], {
      version: 3,
    });
    expect(await screen.findByText("3 versions")).toBeInTheDocument();
  });

  it("agrees with itself about number — one version is singular", async () => {
    show([version()], { version: 1 });
    expect(await screen.findByText("1 version")).toBeInTheDocument();
  });
});

describe("who wrote a version, when it was not a person", () => {
  /** Two of the three actor kinds that appear here are not people, and the one that
   *  matters most is `migration:032`: it marks where an agent's history *starts* rather
   *  than where the agent did, which is the question somebody asks the first time they
   *  open this card on an agent older than the feature. */
  it("says what a migration row is, rather than naming a person who did not act", () => {
    expect(describeAuthor("migration:032")).toBe("before history was kept");
  });

  it("says a seeded row was seeded", () => {
    expect(describeAuthor("system:cli")).toBe("seeded");
  });

  it("shows a person's id unchanged, because there is nothing here to resolve it", () => {
    // `/me` is the only identity this app can resolve and it is not this one. Inventing
    // "someone" would be less true than showing what is stored.
    expect(describeAuthor("user:u_9311cad7")).toBe("u_9311cad7");
  });
});

describe("the request it makes", () => {
  it("re-reads when the agent's version moves, so the list is never one behind", async () => {
    vi.mocked(api.agentVersions).mockResolvedValue([version()]);
    const { rerender } = render(
      <MemoryRouter>
        <VersionHistory agent={AGENT} />
      </MemoryRouter>,
    );
    await screen.findByText("History");
    expect(api.agentVersions).toHaveBeenCalledTimes(1);

    rerender(
      <MemoryRouter>
        <VersionHistory agent={{ ...AGENT, version: 4 }} />
      </MemoryRouter>,
    );

    expect(api.agentVersions).toHaveBeenCalledTimes(2);
  });
});
