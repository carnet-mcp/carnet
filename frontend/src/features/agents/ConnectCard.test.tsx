/** The connect card — the ten minutes between pasting a config and the first call.
 *
 *  What is worth asserting:
 *
 *    - **the address is the server's, never the page's.** `me.mcp_url` is configuration
 *      the bundle cannot know; a card that fell back to `window.location` would be wrong
 *      exactly where deployments get interesting, so the degraded branch is prose
 *    - **the token is a placeholder.** The page never sees a secret and must not invite
 *      pasting one into it
 *    - **the waiting line flips and the poll stops.** Zero polls, nonzero does not — the
 *      card is for the person watching, not a live feed
 */

import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return { ...actual, api: { doorActivity: vi.fn() } };
});

import ConnectCard from "./ConnectCard";
import { api } from "../../lib/api";
import { MeContext } from "../../lib/me";
import type { Me } from "../../lib/types";

const ME: Me = {
  principal: "user:u_9311",
  kind: "user",
  email: "priya@acme.com",
  display_name: "Priya",
  admin: false,
  mcp_url: "https://ship.acme.com/api/mcp",
};

function show(me: Partial<Me> = {}) {
  return render(
    <MeContext.Provider value={{ me: { ...ME, ...me }, settled: true }}>
      <MemoryRouter>
        <ConnectCard name="triage-bot" />
      </MemoryRouter>
    </MeContext.Provider>,
  );
}

beforeEach(() => {
  vi.mocked(api.doorActivity).mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("the address", () => {
  it("shows the MCP server URL and a config a client can hold", async () => {
    vi.mocked(api.doorActivity).mockResolvedValue({ calls: 0, last_call_at: null });
    show();

    expect(
      await screen.findByText("https://ship.acme.com/api/mcp"),
    ).toBeInTheDocument();
    // The snippet carries the URL and a *placeholder* — this page never sees a secret
    // and must not invite pasting one into it. Scoped to the visible pane: 075's tabs
    // mount every dialect and hide all but one.
    const pane = within(screen.getByRole("tabpanel"));
    expect(pane.getByText(/mcpServers/)).toBeInTheDocument();
    expect(pane.getByText(/Bearer <your token>/)).toBeInTheDocument();
  });

  it("degrades to prose when the deployment has not stated its address", async () => {
    // An older API sends no `mcp_url`, and the card must not derive one from its own
    // origin — behind a proxy the app's origin and the door's genuinely differ.
    vi.mocked(api.doorActivity).mockResolvedValue({ calls: 0, last_call_at: null });
    show({ mcp_url: undefined });

    expect(
      await screen.findByText(/The MCP server URL is not configured/),
    ).toBeInTheDocument();
    expect(screen.getByText("CARNET_PUBLIC_ORIGIN")).toBeInTheDocument();
  });

  it("points at Access tokens, where a real token is generated", async () => {
    vi.mocked(api.doorActivity).mockResolvedValue({ calls: 0, last_call_at: null });
    show();

    const links = (await screen.findAllByRole("link")).map((node) =>
      node.getAttribute("href"),
    );
    expect(links).toContain("/tokens");
  });
});

describe("the dialects (075)", () => {
  it("defaults to Claude Code, verified, with the command and where it writes", async () => {
    vi.mocked(api.doorActivity).mockResolvedValue({ calls: 0, last_call_at: null });
    show();

    expect(await screen.findByText(/claude mcp add --transport http carnet/)).toBeInTheDocument();
    expect(screen.getByText(/writes the entry itself/)).toBeInTheDocument();
  });

  it("switches the snippet and says when a dialect was not tried here", async () => {
    vi.mocked(api.doorActivity).mockResolvedValue({ calls: 0, last_call_at: null });
    show();
    await screen.findByText("https://ship.acme.com/api/mcp");

    fireEvent.click(screen.getByRole("tab", { name: "Codex CLI" }));
    const pane = within(screen.getByRole("tabpanel"));
    expect(pane.getByText(/\[mcp_servers\.carnet\]/)).toBeInTheDocument();
    expect(pane.getByText(/Bearer <your token>/)).toBeInTheDocument();
    expect(pane.getByText(/Untested from here/)).toBeInTheDocument();
  });

  it("offers an OAuth client the URL alone, with no token to paste", async () => {
    vi.mocked(api.doorActivity).mockResolvedValue({ calls: 0, last_call_at: null });
    show();
    await screen.findByText("https://ship.acme.com/api/mcp");

    fireEvent.click(screen.getByRole("tab", { name: "Claude.ai and Claude Desktop" }));
    const pane = within(screen.getByRole("tabpanel"));
    expect(pane.queryByText("cannot connect")).not.toBeInTheDocument();
    expect(pane.queryByText(/Bearer <your token>/)).not.toBeInTheDocument();
    expect(pane.getByText(/Add the URL above to/)).toBeInTheDocument();
    expect(pane.getByText(/Add custom connector/)).toBeInTheDocument();
  });

  it("renders the reason instead of a snippet for a client that requires https", async () => {
    vi.mocked(api.doorActivity).mockResolvedValue({ calls: 0, last_call_at: null });
    show({ mcp_url: "http://localhost:8000/mcp" });
    await screen.findByText("http://localhost:8000/mcp");

    fireEvent.click(screen.getByRole("tab", { name: "Claude.ai and Claude Desktop" }));
    const pane = within(screen.getByRole("tabpanel"));
    expect(pane.getByText("cannot connect")).toBeInTheDocument();
    expect(pane.getByText(/requires an https:\/\/ address/)).toBeInTheDocument();
  });
});

describe("waiting for the first call", () => {
  it("says no calls yet, and that it updates by itself", async () => {
    vi.mocked(api.doorActivity).mockResolvedValue({ calls: 0, last_call_at: null });
    show();

    expect(await screen.findByText("no calls yet")).toBeInTheDocument();
    expect(screen.getByText(/updates by itself/)).toBeInTheDocument();
  });

  it("says denied, in the server's words, when the server turned the last call away", async () => {
    // Zero admitted calls and a denial naming one of this agent's tools: the case the
    // card exists for — a token pasted right but not granted this agent — which
    // rendered as "waiting" until 070.
    vi.mocked(api.doorActivity).mockResolvedValue({
      calls: 0,
      last_call_at: null,
      last_refusal: {
        at: "2026-09-03T09:00:00.000+00:00",
        tool: "post_message",
        token: "m_4f2a",
        reason: "grant",
      },
    });
    show();

    expect(await screen.findByText("denied")).toBeInTheDocument();
    expect(screen.getByText(/no agent granted to token m_4f2a provides a tool called 'post_message'/)).toBeInTheDocument();
    expect(screen.queryByText("no calls yet")).not.toBeInTheDocument();
  });

  it("says a token the server does not recognise leaves no record", async () => {
    vi.mocked(api.doorActivity).mockResolvedValue({ calls: 0, last_call_at: null });
    show();

    expect(await screen.findByText(/does not recognise leaves no record/)).toBeInTheDocument();
  });

  it("shows a refusal beside the connected line only when it is newer than the last call", async () => {
    const refusal = {
      at: "2026-08-28T10:00:00.000+00:00",
      tool: "post_message",
      token: "m_4f2a",
      reason: "acting-for",
    };
    vi.mocked(api.doorActivity).mockResolvedValue({
      calls: 3,
      last_call_at: "2026-08-27T10:00:00.000+00:00",
      last_refusal: refusal,
    });
    const first = show();
    expect(await screen.findByText("connected")).toBeInTheDocument();
    expect(screen.getByText("denied since")).toBeInTheDocument();
    expect(screen.getByText(/on-behalf-of claim the server could not accept/)).toBeInTheDocument();
    first.unmount();

    // Older than the last admitted call: not news, and not shown.
    vi.mocked(api.doorActivity).mockResolvedValue({
      calls: 3,
      last_call_at: "2026-08-29T10:00:00.000+00:00",
      last_refusal: refusal,
    });
    show();
    expect(await screen.findByText("connected")).toBeInTheDocument();
    expect(screen.queryByText("denied since")).not.toBeInTheDocument();
  });

  it("flips to connected when calls have arrived", async () => {
    vi.mocked(api.doorActivity).mockResolvedValue({
      calls: 3,
      last_call_at: "2026-08-27T10:00:00.000+00:00",
    });
    show();

    expect(await screen.findByText("connected")).toBeInTheDocument();
    expect(screen.getByText(/3 requests/)).toBeInTheDocument();
  });

  it("polls while waiting, and stops at first contact", async () => {
    // Fake timers from the start, so the interval itself is under the test's clock;
    // `getByText` (sync) throughout, because `findByText`'s waitFor and fake timers
    // deadlock each other.
    vi.useFakeTimers();
    vi.mocked(api.doorActivity)
      .mockResolvedValueOnce({ calls: 0, last_call_at: null })
      .mockResolvedValue({ calls: 1, last_call_at: "2026-08-27T10:00:00.000+00:00" });
    show();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0); // the initial load resolves
    });
    expect(screen.getByText("no calls yet")).toBeInTheDocument();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_100); // one poll tick
    });
    expect(screen.getByText("connected")).toBeInTheDocument();
    const afterContact = vi.mocked(api.doorActivity).mock.calls.length;

    // Nonzero does not poll: two more would-be ticks ask nothing further.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(11_000);
    });
    expect(vi.mocked(api.doorActivity).mock.calls.length).toBe(afterContact);
  });
});
