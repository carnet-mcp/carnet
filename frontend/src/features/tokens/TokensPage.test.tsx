/** Your tokens, and the things this page must not get wrong.
 *
 * Most of it is a table and a table is not worth asserting. What is:
 *
 *   - **personal and service are visibly different.** This is the chunk's whole point.
 *     `acts_as_owner` decides whether a credential reaches its owner's entire access or
 *     only its own grants, and until 035c it was dropped between the store and the wire —
 *     so a page that rendered it identically would have closed the gap on paper only
 *   - **a failed listing is not an empty listing.** The replacement for the 403 the admin
 *     pages assert, which this page cannot produce; and not an invented property, because
 *     a card once shipped the wrong branch one screen over, and its docstring recorded
 *     it — a 503 made the form say *you have no machine* about a token the person may
 *     well have owned
 *   - **dead tokens are listed and marked.** The listing is a record and the *picker* is
 *     what excludes; hiding them answers "you have no tokens" to somebody with three dead
 *     ones and hides the reason a schedule stopped firing
 *   - **minting is a session's act, for itself.** Step 044 reversed category 2 of plan
 *     035 on purpose — the route refuses machine callers, which is what the rule always
 *     protected — so the assertions are about the new rule's shape: no owner field, a
 *     secret shown once, expiry spelled by omission
 */

import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return { ...actual, api: { myTokens: vi.fn(), mintToken: vi.fn() } };
});

import TokensPage from "./TokensPage";
import { api, ApiError } from "../../lib/api";
import { MeContext } from "../../lib/me";
import type { OwnedToken } from "../../lib/types";

function token(overrides: Partial<OwnedToken> = {}): OwnedToken {
  return {
    id: "m_8f2c1a",
    name: "nightly-ci",
    owner_id: "u_priya",
    acts_as_owner: false,
    created_by: "system:cli",
    created_at: "2026-08-01T09:00:00+00:00",
    expires_at: null,
    revoked_at: null,
    revoked_by: null,
    last_used_at: null,
    ...overrides,
  };
}

function show(rows: OwnedToken[]) {
  vi.mocked(api.myTokens).mockResolvedValue(rows);
  return render(
    <MemoryRouter>
      <TokensPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(api.myTokens).mockReset();
  vi.mocked(api.mintToken).mockReset();
});

describe("the listing", () => {
  it("names each token and the id its records will actually say", async () => {
    // The id, not just the name: every record a machine writes says `machine:m_8f2c1a`
    // — in an audit row, in a denial, in a run's principal — and somebody holding one of
    // those strings comes here to find out whose it is.
    show([token()]);

    expect(await screen.findByText("nightly-ci")).toBeInTheDocument();
    expect(screen.getByText("m_8f2c1a")).toBeInTheDocument();
  });

  it("asks for the listing once and does not poll it", async () => {
    show([token()]);
    await screen.findByText("nightly-ci");

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(api.myTokens).toHaveBeenCalledTimes(1);
  });
});

describe("personal and service", () => {
  it("tells apart a token that acts as its owner from one that does not", async () => {
    // The assertion this whole chunk exists for, and it failed at every layer until now:
    // the column has been real since migration 042 and the wire dropped it silently,
    // because the server's model never declared it.
    show([
      token({ id: "m_cursor", name: "priya-cursor", acts_as_owner: true }),
      token({ id: "m_ci", name: "nightly-ci", acts_as_owner: false }),
    ]);

    const rows = await screen.findAllByRole("row");
    expect(within(rows[1]).getByText("personal")).toBeInTheDocument();
    expect(within(rows[2]).getByText("service")).toBeInTheDocument();
  });

  it("says what personal means rather than only labelling it", async () => {
    // A badge reading "personal" is a word somebody has to already know. The consequence
    // — this credential reaches whatever its owner reaches — is the fact an offboarding
    // review is actually looking for.
    show([token({ acts_as_owner: true })]);

    expect(await screen.findByText(/capped at user/)).toBeInTheDocument();
  });
});

describe("what happened to a token", () => {
  it("lists a revoked token rather than hiding it, and marks it", async () => {
    // The listing is a record; the picker is what excludes. A page that filtered these
    // would answer "you have no tokens" to somebody who has three dead ones, and would
    // hide the most likely reason they opened this page at all.
    show([token({ revoked_at: "2026-08-20T10:00:00+00:00", revoked_by: "system:cli" })]);

    expect(await screen.findByText("revoked")).toBeInTheDocument();
    expect(screen.getByText("nightly-ci")).toBeInTheDocument();
  });

  it("names who revoked it, not only when", async () => {
    // The case the column exists for: a token revoked by an administrator rather than by
    // its owner. "revoked" with no actor leaves the person holding it with nobody to ask.
    show([
      token({ revoked_at: "2026-08-20T10:00:00+00:00", revoked_by: "user:u_ops" }),
    ]);

    expect(await screen.findByText(/by user:u_ops/)).toBeInTheDocument();
  });

  it("says nothing about an actor when the row carries none", async () => {
    // `revoked_by` is `""` rather than null on a row that was never revoked, and both
    // stores write the empty string — so "revoked by " with nothing after it is one
    // careless ternary away, and it reads as a name that went missing.
    show([token({ revoked_at: "2026-08-20T10:00:00+00:00", revoked_by: "" })]);

    await screen.findByText("revoked");
    expect(screen.queryByText(/ by $/)).not.toBeInTheDocument();
  });

  it("marks a token whose expiry has passed", async () => {
    show([token({ expires_at: "2020-01-01T00:00:00+00:00" })]);

    expect(await screen.findByText("expired")).toBeInTheDocument();
  });

  it("prefers revoked over expired, because revoking is the deliberate act", async () => {
    // Somebody who revoked a token before its expiry date made a decision, and should be
    // able to see that they made it. (`--list-tokens` also puts revoked first — what it
    // does *not* do is ever say "expired", because it has one column and packs the
    // instant into it. See `State`.)
    show([
      token({
        expires_at: "2020-01-01T00:00:00+00:00",
        revoked_at: "2019-06-01T00:00:00+00:00",
      }),
    ]);

    expect(await screen.findByText("revoked")).toBeInTheDocument();
    expect(screen.queryByText("expired")).not.toBeInTheDocument();
  });

  it("renders a token that has never been used as a word rather than a blank cell", async () => {
    // `DoorTrafficPage`'s "nobody named" and `DenialsPage`'s "nothing", one screen over:
    // an empty value here is an answer the server gave, and *never used* is precisely
    // what an offboarding review came to read. A blank cell reads as a field that failed
    // to arrive.
    show([token({ last_used_at: null })]);

    const rows = await screen.findAllByRole("row");
    const cells = within(rows[1]).getAllByRole("cell");
    expect(cells[4]).toHaveTextContent("never");
  });
});

describe("having none", () => {
  it("says so, and says where tokens come from", async () => {
    // Which is *here*, since 044 — the empty state points at the form below rather
    // than at the terminal.
    show([]);

    expect(await screen.findByText("You have no tokens")).toBeInTheDocument();
    expect(screen.getByText("Mint one below.", { exact: false })).toBeInTheDocument();
  });
});

// Plan 035 category 2 said the assertions this block replaced would be the ones
// somebody deleted out of helpfulness. Step 044 reversed the policy on purpose — the
// route refuses machine callers, which is what the old rule actually protected — so
// what is asserted now is the new rule's shape: a form that mints for *you*, a secret
// shown once, and nothing that could name another owner.
describe("minting", () => {
  it("is closed by default, and opens into a form", async () => {
    show([]);

    fireEvent.click(await screen.findByRole("button", { name: "Mint a token" }));

    expect(screen.getByText("Personal — acts as you.")).toBeInTheDocument();
    expect(screen.getByText("Service — holds only its own grants.")).toBeInTheDocument();
    // No owner field: the route mints for its caller, always.
    expect(screen.queryByText(/owner/i)).not.toBeInTheDocument();
  });

  it("will not mint without a name", async () => {
    show([]);

    fireEvent.click(await screen.findByRole("button", { name: "Mint a token" }));

    expect(screen.getByRole("button", { name: "Mint this token" })).toBeDisabled();
  });

  it("mints, shows the secret once, and says it cannot be retrieved", async () => {
    vi.mocked(api.mintToken).mockResolvedValue({
      ...token({ name: "my-assistant", acts_as_owner: true }),
      token: "art_m_9f2c.SECRET-SHOWN-ONCE",
    });
    show([]);

    fireEvent.click(await screen.findByRole("button", { name: "Mint a token" }));
    fireEvent.change(screen.getByRole("textbox", { name: /Name/ }), {
      target: { value: "my-assistant" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Mint this token" }));

    expect(await screen.findByText("art_m_9f2c.SECRET-SHOWN-ONCE")).toBeInTheDocument();
    expect(
      screen.getByText("shown once and cannot be retrieved", { exact: false }),
    ).toBeInTheDocument();
    expect(vi.mocked(api.mintToken)).toHaveBeenCalledWith({
      name: "my-assistant",
      acts_as_owner: true,
    });
    // And the listing was re-read, so the new row appears without a reload.
    expect(vi.mocked(api.myTokens).mock.calls.length).toBeGreaterThan(1);
  });

  it("sends expiry only when one was typed — no expiry is spelled by omission", async () => {
    vi.mocked(api.mintToken).mockResolvedValue({
      ...token({ name: "short-lived" }),
      token: "art_m_1.x",
    });
    show([]);

    fireEvent.click(await screen.findByRole("button", { name: "Mint a token" }));
    fireEvent.change(screen.getByRole("textbox", { name: /Name/ }), {
      target: { value: "short-lived" },
    });
    fireEvent.change(screen.getByRole("textbox", { name: /Expires/ }), {
      target: { value: "30" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Mint this token" }));

    await screen.findByText("art_m_1.x");
    expect(vi.mocked(api.mintToken)).toHaveBeenCalledWith({
      name: "short-lived",
      acts_as_owner: true,
      expires_days: 30,
    });
  });

  it("renders the server's own sentence when the mint is refused", async () => {
    vi.mocked(api.mintToken).mockRejectedValue(
      new ApiError(
        400,
        "this customer already has a live API token called 'nightly-ci'.",
      ),
    );
    show([token()]);

    fireEvent.click(await screen.findByRole("button", { name: "Mint a token" }));
    fireEvent.change(screen.getByRole("textbox", { name: /Name/ }), {
      target: { value: "nightly-ci" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Mint this token" }));

    expect(
      await screen.findByText(/already has a live API token/),
    ).toBeInTheDocument();
    // The form is still there with what was typed — a refusal is not a reset.
    expect(screen.getByRole("button", { name: "Mint this token" })).toBeInTheDocument();
  });

  it("says what a service token still needs, because it can run nothing yet", async () => {
    vi.mocked(api.mintToken).mockResolvedValue({
      ...token({ name: "ci", acts_as_owner: false, id: "m_svc1" }),
      token: "art_m_svc1.y",
    });
    show([]);

    fireEvent.click(await screen.findByRole("button", { name: "Mint a token" }));
    fireEvent.change(screen.getByRole("textbox", { name: /Name/ }), {
      target: { value: "ci" },
    });
    fireEvent.click(screen.getByText("Service — holds only its own grants."));
    fireEvent.click(screen.getByRole("button", { name: "Mint this token" }));

    await screen.findByText("art_m_svc1.y");
    expect(screen.getByText("It can run nothing yet.", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("machine:m_svc1")).toBeInTheDocument();
  });
});

describe("when the listing cannot be read", () => {
  it("shows the server's own sentence", async () => {
    vi.mocked(api.myTokens).mockRejectedValue(
      new ApiError(503, "storage unavailable"),
    );

    render(
      <MemoryRouter>
        <TokensPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText(/storage unavailable/)).toBeInTheDocument();
  });

  it("never says you have no tokens when what happened is that it could not ask", async () => {
    // **The replacement for the 403 every admin page asserts**, because this route is
    // deliberately roleless and cannot produce one — decided rather than substituted.
    //
    // Not a hypothetical either: a card once shipped this exact fall-through, and its
    // docstring records it — "A failed token listing is not an answer about tokens", where
    // a 503 made the form say *you have no machine* and point at `--mint-token`, about a
    // token the person may well have owned. Here the same missing branch would say "you
    // have no credentials" to somebody who has four, on the page they opened to check.
    vi.mocked(api.myTokens).mockRejectedValue(new ApiError(503, "storage unavailable"));

    render(
      <MemoryRouter>
        <TokensPage />
      </MemoryRouter>,
    );

    await screen.findByText(/storage unavailable/);
    expect(screen.queryByText("You have no tokens")).not.toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });
});
describe("the door, on the page that mints its key (062)", () => {
  // The endpoint and the client snippet used to live only on an agent's detail page
  // - unreachable for a fresh deployment's first administrator, who has no agent
  // yet - and nothing here named the URL a token is FOR.
  it("shows the endpoint and the snippet when the deployment knows its address", async () => {
    vi.mocked(api.myTokens).mockResolvedValue([]);
    render(
      <MeContext.Provider
        value={{
          me: {
            principal: "user:u_9311",
            kind: "user",
            email: "priya@acme.com",
            display_name: "Priya",
            admin: true,
            mcp_url: "https://acme.example/api/mcp",
          },
          settled: true,
        }}
      >
        <MemoryRouter>
          <TokensPage />
        </MemoryRouter>
      </MeContext.Provider>,
    );

    expect(
      await screen.findByText("https://acme.example/api/mcp"),
    ).toBeInTheDocument();
    // Scoped to the visible pane: 075's dialect tabs mount every snippet, hidden.
    expect(within(screen.getByRole("tabpanel")).getByText(/mcpServers/)).toBeInTheDocument();
    // The token prose points at THIS page rather than linking to itself.
    expect(screen.getByText(/on this page/)).toBeInTheDocument();
  });

  it("degrades to the operator prose when the address is unknown", async () => {
    show([]);

    expect(await screen.findByText(/CARNET_PUBLIC_ORIGIN/)).toBeInTheDocument();
  });
});
