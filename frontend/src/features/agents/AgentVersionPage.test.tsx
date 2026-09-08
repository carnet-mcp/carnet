/** One version, and the button that puts it back.
 *
 * The two things worth asserting here are both about **not offering an action that will
 * fail**: a version this workspace can no longer accept has its Restore disabled with the
 * server's own sentence beside it, and somebody without `editor` is offered nothing at
 * all. That is 10d's `your_role` lesson — a control that refuses the person who pressed
 * it reads as a bug — applied to the one write this screen has.
 *
 * The third is the sentence under the button, which exists because a restore is not what
 * people expect: it writes a **new** version rather than moving a pointer back, so
 * nothing is lost and the restore is itself undoable.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return {
    ...actual,
    api: {
      getAgent: vi.fn(),
      getAgentVersion: vi.fn(),
      restoreAgentVersion: vi.fn(),
      listTools: vi.fn(),
    },
  };
});

import AgentVersionPage from "./AgentVersionPage";
import { api, ApiError } from "../../lib/api";
import type { AgentDetail, AgentVersion } from "../../lib/types";

const AGENT: AgentDetail = {
  name: "minimal",
  runtime: "simple",
  tools: ["post_message"],
  valid: true,
  error: null,
  system: "Now.",
  scope: { "chat.channel": { write: ["#eng"] } },
  limits: {},
  updated_at: "2026-08-13T04:12:33.482391+00:00",
  your_role: "owner",
  version: 3,
  config: { name: "minimal", system: "Now." },
};

const STORED: AgentVersion = {
  version: 1,
  created_at: "2026-08-01T04:12:33.482391+00:00",
  created_by: "user:u_9311cad7",
  source: "update",
  restored_from: null,
  valid: true,
  error: null,
  config: {
    name: "minimal",
    system: "What it said before.",
    permissions: { tools: ["post_message"], scope: { "chat.channel": { write: ["#eng"] } } },
  },
};

function show(stored: Partial<AgentVersion> = {}, agent: Partial<AgentDetail> = {}) {
  vi.mocked(api.getAgent).mockResolvedValue({ ...AGENT, ...agent });
  vi.mocked(api.getAgentVersion).mockResolvedValue({ ...STORED, ...stored });
  vi.mocked(api.listTools).mockResolvedValue([]);
  render(
    <MemoryRouter initialEntries={["/agents/minimal/versions/1"]}>
      <Routes>
        <Route path="/agents/:name/versions/:version" element={<AgentVersionPage />} />
        <Route path="/agents/:name" element={<p>the agent page</p>} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(api.getAgent).mockReset();
  vi.mocked(api.getAgentVersion).mockReset();
  vi.mocked(api.restoreAgentVersion).mockReset();
  vi.mocked(api.listTools).mockReset();
});

describe("what this version said", () => {
  it("shows the stored instructions rather than the live ones", async () => {
    show();

    expect(await screen.findByText("What it said before.")).toBeInTheDocument();
    expect(screen.queryByText("Now.")).not.toBeInTheDocument();
  });

  it("says when it was saved and by whom, without inventing a person", async () => {
    show({ created_by: "migration:032" });

    expect(await screen.findByText(/before history was kept/)).toBeInTheDocument();
  });
});

describe("restoring", () => {
  it("says what will happen, because a restore is not what people expect", async () => {
    show();

    // The new version's number, the two that survive, and the reversibility — all three
    // said before the click rather than discovered from the history afterwards.
    expect(await screen.findByText(/This becomes v4/)).toBeInTheDocument();
    expect(screen.getByText(/stays where it is/)).toBeInTheDocument();
  });

  it("sends the agent's ETag, so a save underneath it is refused rather than lost", async () => {
    show();
    vi.mocked(api.restoreAgentVersion).mockResolvedValue(AGENT);
    await userEvent.click(await screen.findByRole("button", { name: "Restore v1" }));

    await waitFor(() =>
      expect(api.restoreAgentVersion).toHaveBeenCalledWith(
        "minimal",
        1,
        AGENT.updated_at,
      ),
    );
  });

  it("refuses a version that would no longer validate, and says why", async () => {
    show({
      valid: false,
      error: "agent 'minimal' is granted 'notes_read_page', which is not a registered tool",
    });

    expect(await screen.findByText(/notes_read_page/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Restore v1" })).toBeDisabled();
  });

  it("offers nothing to somebody who may only run the agent", async () => {
    show({}, { your_role: "user" });

    await screen.findByText("What it said before.");
    expect(screen.queryByRole("button", { name: /Restore/ })).not.toBeInTheDocument();
  });

  it("offers no restore of the version that is already live", async () => {
    show({ version: 3 }, { version: 3 });

    await screen.findByText("What it said before.");
    expect(screen.queryByRole("button", { name: /Restore/ })).not.toBeInTheDocument();
    expect(screen.getByText(/this is the version running now/)).toBeInTheDocument();
  });

  it("renders a 409 as what happened rather than as a failure", async () => {
    show();
    vi.mocked(api.restoreAgentVersion).mockRejectedValue(
      new ApiError(409, "somebody else changed this agent", {
        changed: ["system"],
        updated_at: "2026-08-13T05:00:00+00:00",
      }),
    );

    await userEvent.click(await screen.findByRole("button", { name: "Restore v1" }));

    // There is no in-progress edit to lose here, so the answer is to look again — and
    // deliberately not a "restore anyway", which is the whole thing the refusal is for.
    expect(
      await screen.findByText(/Somebody else saved while this was open/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Nothing was written/)).toBeInTheDocument();
  });
});

describe("a mangled URL", () => {
  it("answers a non-numeric version like a missing one, without a request", async () => {
    // `Number("abc")` is NaN, and the request it would make comes back as FastAPI's
    // list-shaped 422 — which the generic handler renders as "this agent's
    // configuration is not valid", a sentence about a different situation entirely.
    vi.mocked(api.getAgent).mockResolvedValue(AGENT);
    vi.mocked(api.listTools).mockResolvedValue([]);
    render(
      <MemoryRouter initialEntries={["/agents/minimal/versions/abc"]}>
        <Routes>
          <Route path="/agents/:name/versions/:version" element={<AgentVersionPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText(/not a version of anything/)).toBeInTheDocument();
    expect(api.getAgentVersion).not.toHaveBeenCalled();
  });
});
