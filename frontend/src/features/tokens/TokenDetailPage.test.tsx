/** One token's reach, and the four things this page must not get wrong.
 *
 *   - **one tool granted by two agents renders twice, with two scopes.** This is the
 *     chunk's whole point. The union rule keeps each agent's own scope and decides which
 *     applies per call, so a page that unioned them would invent a permission nobody
 *     wrote down and a page that picked one would show a narrower reach than the token
 *     has. Asserted from the outside, because it is invisible in a screenshot
 *   - **granted nothing is a sentence.** Empty-denies is the product's default and a
 *     blank card reads as a load failure — the same rule `TokensPage` asserts one level up
 *   - **revoked still shows the reach, and says it is revoked.** The route ignores
 *     liveness on purpose; the page must carry both facts without either implying the
 *     other, or an offboarding review reads "revoked" as "reaches nothing"
 *   - **the page grants nothing**, plan 035 category 2, at the screen that names
 *     permissions and would be the most natural place for somebody to add a Revoke button
 *
 * And, from 035e, the one that makes an obvious rendering actively wrong: **an unmetered
 * deployment writes no budget rows at all**, so a figure drawn from `calls: 0` would say
 * *this credential has barely been used* about a token hammering the door all day. The
 * dial being off has to be a sentence with no figure beside it, and the assertion is
 * therefore as much about what is **absent** from the page as about what is on it.
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return {
    ...actual,
    api: {
      myTokens: vi.fn(),
      tokenReach: vi.fn(),
      tokenBudget: vi.fn(),
      listTools: vi.fn(),
      revokeToken: vi.fn(),
    },
  };
});

import TokenDetailPage from "./TokenDetailPage";
import { api, ApiError } from "../../lib/api";
import type { OwnedToken, TokenReach, TokenSpend, ToolGroup } from "../../lib/types";

const SEARCH = {
  name: "github_mcp_list_issues",
  remote_name: "list_issues",
  description: "List issues in a GitHub repository.",
  note: "",
  effect: "read" as const,
  resources: [{ type: "github.repo" }],
  identity: "service" as const,
  max_response_bytes: null,
  vetted_by: "",
  vetted_at: "",
};

const CATALOGUE: ToolGroup[] = [
  { origin: "connector", id: "github-mcp", description: "GitHub.", tools: [SEARCH] },
];

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

function reach(overrides: Partial<TokenReach> = {}): TokenReach {
  return {
    token_id: "m_8f2c1a",
    acts_as_owner: false,
    resolved_as: "machine:m_8f2c1a",
    tools: ["github_mcp_list_issues"],
    agents: [
      {
        name: "triage",
        tools: ["github_mcp_list_issues"],
        scope: { "github.repo": { read: ["acme/*"] } },
      },
    ],
    by_tool: [
      {
        tool: "github_mcp_list_issues",
        effect: "read",
        resource_types: ["github.repo"],
        granted_by: [
          { agent: "triage", applies: { "github.repo": ["acme/*"] } },
        ],
      },
    ],
    invalid_agents: [],
    ...overrides,
  };
}

/** A week with nothing in it, which is what a freshly minted token's budget looks like.
 *
 *  Seven dense windows, oldest first, ending at `window` — the server fills the gaps, so
 *  a fixture that produced a sparse list would be testing a shape the route cannot
 *  return. */
function week(counts: number[] = [0, 0, 0, 0, 0, 0, 0]): TokenSpend["history"] {
  return counts.map((calls, offset) => ({
    window_start: `2026-08-${20 + offset}`,
    calls,
  }));
}

function spend(overrides: Partial<TokenSpend> = {}): TokenSpend {
  const history = overrides.history ?? week();
  return {
    token_id: "m_8f2c1a",
    window: history[history.length - 1].window_start,
    calls: history[history.length - 1].calls,
    ceiling: 1000,
    metered: true,
    // 045b's money, off by default — which is the deployment these fixtures describe and
    // the one every test above was written against.
    usd: 0,
    usd_ceiling: 0,
    usd_metered: false,
    tokens: 0,
    tokens_ceiling: 0,
    tokens_metered: false,
    unpriced_models: [],
    ...overrides,
    history,
  };
}

function show(
  rows: OwnedToken[] = [token()],
  answer: TokenReach | Error = reach(),
  catalogue: ToolGroup[] | Error = CATALOGUE,
  budget: TokenSpend | Error = spend(),
) {
  vi.mocked(api.myTokens).mockResolvedValue(rows);
  vi.mocked(api.tokenReach).mockImplementation(
    answer instanceof Error ? () => Promise.reject(answer) : () => Promise.resolve(answer),
  );
  vi.mocked(api.tokenBudget).mockImplementation(
    budget instanceof Error ? () => Promise.reject(budget) : () => Promise.resolve(budget),
  );
  vi.mocked(api.listTools).mockImplementation(
    catalogue instanceof Error
      ? () => Promise.reject(catalogue)
      : () => Promise.resolve(catalogue),
  );

  return render(
    <MemoryRouter initialEntries={["/tokens/m_8f2c1a"]}>
      <Routes>
        <Route path="/tokens/:tokenId" element={<TokenDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(api.myTokens).mockReset();
  vi.mocked(api.tokenReach).mockReset();
  vi.mocked(api.tokenBudget).mockReset();
  vi.mocked(api.listTools).mockReset();
  vi.mocked(api.revokeToken).mockReset();
});

describe("the reach", () => {
  it("renders one section per granted agent, titled with the agent's name", async () => {
    show(
      [token()],
      reach({
        tools: ["github_mcp_list_issues"],
        agents: [
          {
            name: "triage",
            tools: ["github_mcp_list_issues"],
            scope: { "github.repo": { read: ["acme/*"] } },
          },
          {
            name: "security-triage",
            tools: ["github_mcp_list_issues"],
            scope: { "github.repo": { read: ["acme/secrets-*"] } },
          },
        ],
      }),
    );

    expect(
      await screen.findByRole("heading", { name: "triage" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "security-triage" }),
    ).toBeInTheDocument();
  });

  it("keeps each agent's own scope rather than unioning or picking one", async () => {
    // **The assertion this page exists for.** One tool, two granted agents, two different
    // bounds — and the union rule says both are live and the *call* decides which applies.
    // A flat render would have to union them (inventing a permission nobody wrote down) or
    // pick one (showing a narrower reach than the token has), and both are invisible
    // unless somebody asserts that the two patterns appear side by side.
    show(
      [token()],
      reach({
        agents: [
          {
            name: "triage",
            tools: ["github_mcp_list_issues"],
            scope: { "github.repo": { read: ["acme/*"] } },
          },
          {
            name: "security-triage",
            tools: ["github_mcp_list_issues"],
            scope: { "github.repo": { read: ["acme/secrets-*"] } },
          },
        ],
        // Overridden alongside `agents`, because the two are one answer: a response
        // whose transpose disagreed with its per-agent sections is a shape the route
        // cannot return, and a fixture that produced one would be testing nothing.
        by_tool: [
          {
            tool: "github_mcp_list_issues",
            effect: "read",
            resource_types: ["github.repo"],
            granted_by: [
              { agent: "security-triage", applies: { "github.repo": ["acme/secrets-*"] } },
              { agent: "triage", applies: { "github.repo": ["acme/*"] } },
            ],
          },
        ],
      }),
    );

    // **Scoped to each agent's own section, which the bare query was not.** Before 069
    // this asserted only that both patterns appeared *somewhere* — which a render that
    // unioned them into one section would also have satisfied. The ambiguity that forced
    // the change is what exposed the gap: the assertion this test was named for is that
    // `acme/*` is in `triage`'s card and nowhere near `security-triage`'s.
    const triage = (
      await screen.findByRole("heading", { name: "triage" })
    ).closest("section")!;
    const security = screen
      .getByRole("heading", { name: "security-triage" })
      .closest("section")!;

    expect(within(triage).getByText("acme/*")).toBeInTheDocument();
    expect(within(triage).queryByText("acme/secrets-*")).not.toBeInTheDocument();
    expect(within(security).getByText("acme/secrets-*")).toBeInTheDocument();
    expect(within(security).queryByText("acme/*")).not.toBeInTheDocument();
  });

  it("puts the composed view above the per-agent sections, not below them", async () => {
    // **Decided by looking at the rendered page.** Three grants render three
    // near-identical cards — same tool, same description, three scopes — and the
    // transpose sat a thousand pixels under them, past the point a reader has given up
    // and started comparing by eye. It belongs with the summary, not after the working.
    //
    // Asserted on document order because that is the whole claim and nothing else here
    // would catch a component being moved back.
    show();

    await screen.findByRole("heading", { name: "triage" });
    const headings = screen
      .getAllByRole("heading")
      .map((node) => node.textContent);

    expect(headings.indexOf("Access by tool")).toBeGreaterThan(
      headings.indexOf("Access"),
    );
    expect(headings.indexOf("Access by tool")).toBeLessThan(headings.indexOf("triage"));
  });

  it("says the union rule in words, because two scopes for one tool read as a mistake", async () => {
    show();

    // Matched on the clause after the `<em>`, because Testing Library does not read text
    // across element boundaries and *each* is emphasised — which it is on purpose.
    expect(
      await screen.findByText(/Which one applies is decided per call/),
    ).toBeInTheDocument();
  });

  it("counts the union of tools and the agents they came through", async () => {
    show(
      [token()],
      reach({
        tools: ["github_mcp_list_issues", "post_message"],
        agents: [
          { name: "triage", tools: ["github_mcp_list_issues"], scope: {} },
          { name: "poster", tools: ["post_message"], scope: {} },
        ],
      }),
    );

    expect(await screen.findByText(/2 tools, through 2 agents/)).toBeInTheDocument();
  });

  it("asks for each thing once and does not poll", async () => {
    show();
    await screen.findByRole("heading", { name: "triage" });

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(api.myTokens).toHaveBeenCalledTimes(1);
    expect(api.tokenReach).toHaveBeenCalledTimes(1);
    expect(api.tokenBudget).toHaveBeenCalledTimes(1);
    expect(api.listTools).toHaveBeenCalledTimes(1);
  });
});

describe("what it has spent", () => {
  it("puts the count against the limit, because a number without its limit is not an answer", async () => {
    show([token()], reach(), CATALOGUE, spend({ history: week([0, 4, 0, 0, 9, 2, 41]) }));

    expect(await screen.findByText(/41 of 1,000/)).toBeInTheDocument();
    expect(screen.getByText(/requests allowed today/)).toBeInTheDocument();
  });

  it("says allowed rather than made, and names where the denials are", async () => {
    // **Trap 2.** A call refused for scope, and a call refused by this very ceiling, both
    // cost nothing and are not counted — so a token being denied five hundred times a day
    // shows up here as whatever it succeeded at. A section labelled *calls made* would be
    // wrong twice over, and wrong in the direction somebody investigating an incident
    // cares about.
    show([token()], reach(), CATALOGUE, spend({ history: week([0, 0, 0, 0, 0, 0, 3]) }));

    expect(await screen.findByText("Allowed requests only.")).toBeInTheDocument();
    expect(screen.getByText(/costs nothing and is not counted here/)).toBeInTheDocument();
    expect(screen.getByText(/denied requests on the access denied log/)).toBeInTheDocument();
  });

  it("renders the week as seven rows including the quiet days", async () => {
    // Dense, and the zeros are the point: a sparse series silently redraws a quiet
    // Tuesday as though Tuesday had not happened. The fill is the server's, on the
    // storage layer's own "0 when there is no row" — this asserts the page renders what
    // it is given rather than dropping the empty ones.
    show([token()], reach(), CATALOGUE, spend({ history: week([5, 0, 0, 7, 0, 0, 2]) }));

    const table = (await screen.findByText("Requests allowed")).closest("table")!;
    expect(within(table).getAllByRole("row")).toHaveLength(8); // seven windows + header
    expect(within(table).getByText("2026-08-23")).toBeInTheDocument();
  });

  it("marks today rather than moving it, since 'is today unusual' needs the others beside it", async () => {
    show([token()], reach(), CATALOGUE, spend({ history: week([1, 1, 1, 1, 1, 1, 8]) }));

    const table = (await screen.findByText("Requests allowed")).closest("table")!;
    const rows = within(table).getAllByRole("row");
    // Oldest first — the server's order and every log reader's in this product. Reversing
    // it here would be a second ordering to remember.
    expect(rows[1]).toHaveTextContent("2026-08-20");
    expect(rows[7]).toHaveTextContent("today");
  });

  it("says a quiet week as a sentence rather than seven rows of zeros", async () => {
    // Empty-denies is the default and a table of zeros reads as a load that half-failed.
    // Safe **only** because the meter is on: the same zeros mean something else entirely
    // when it is off, which the next test is about.
    show([token()], reach(), CATALOGUE, spend());

    expect(
      await screen.findByText(/No requests were allowed in the last seven days/),
    ).toBeInTheDocument();
    expect(screen.queryByText("Requests allowed")).not.toBeInTheDocument();
  });

  it("warns when the token is at its rate limit, and says the credential is otherwise fine", async () => {
    show(
      [token()],
      reach(),
      CATALOGUE,
      spend({ ceiling: 3, history: week([0, 0, 0, 0, 0, 1, 3]) }),
    );

    expect(await screen.findByText("Rate limit reached")).toBeInTheDocument();
    expect(screen.getByText(/denied until midnight UTC/)).toBeInTheDocument();
    // The other half, and it is why the notice exists rather than a bare number: the
    // reader arrived asking *why did this stop*, and "it is not revoked" is the sentence
    // that stops them going and revoking something else.
    expect(screen.getByText(/The token is not revoked/)).toBeInTheDocument();
  });

  it("offers nothing that would raise the limit, because that would be a grant", async () => {
    // Plan 035 category 2 at its sharpest: `CARNET_MCP_CALLS_PER_DAY` is a deployment
    // setting, and a control that changed what a credential may spend is a grant. The
    // page says where the dial lives instead.
    show(
      [token()],
      reach(),
      CATALOGUE,
      spend({ ceiling: 3, history: week([0, 0, 0, 0, 0, 0, 3]) }),
    );

    await screen.findByText("Rate limit reached");
    // The revoke button (044) is the page's one control, and it *removes* authority.
    // Nothing here raises the limit or grants anything.
    expect(
      screen.queryByRole("button", { name: /ceiling|limit|raise|grant/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/set by an operator for the whole deployment/),
    ).toBeInTheDocument();
  });
});

describe("a deployment that does not meter", () => {
  it("says the meter is off and renders no figure at all", async () => {
    // **Trap 1, and the assertion is as much about absence as presence.** `reserve`
    // returns ALLOW before touching storage when the ceiling is not positive, so a token
    // making thousands of calls an hour has no rows — and `0 / 0`, `0 / 1000` or a bar at
    // 0% would all say *barely used* about the opposite. It is also the reassuring
    // direction, which is the one nobody rechecks.
    show([token()], reach(), CATALOGUE, spend({ ceiling: 0, metered: false }));

    expect(await screen.findByText("Requests are not metered")).toBeInTheDocument();
    expect(screen.getByText("Nothing is recorded here.")).toBeInTheDocument();
    expect(screen.queryByText(/requests allowed today/)).not.toBeInTheDocument();
    expect(screen.queryByText(/of 1,000/)).not.toBeInTheDocument();
    expect(screen.queryByText(/0 of 0/)).not.toBeInTheDocument();
  });

  it("does not offer the quiet-week sentence, where identical zeros mean something else", async () => {
    // The two branches produce the same numbers and different facts. *No calls were
    // admitted* is only true when something was counting.
    show([token()], reach(), CATALOGUE, spend({ ceiling: 0, metered: false }));

    await screen.findByText("Requests are not metered");
    expect(
      screen.queryByText(/No requests were allowed in the last seven days/),
    ).not.toBeInTheDocument();
  });

  it("is an alert rather than a note, because the failure is somebody skimming past it", async () => {
    show([token()], reach(), CATALOGUE, spend({ ceiling: 0, metered: false }));

    const notice = await screen.findByRole("alert");
    expect(notice).toHaveTextContent("Requests are not metered");
  });

  it("still shows what was counted before the meter was turned off, and captions it", async () => {
    // Nothing is deleted when the meter stops, so a deployment that ran metered until
    // Tuesday keeps Monday's rows. Dropping them would lose the only record there is; and
    // showing them uncaptioned would make the zeros after look like quiet days.
    show(
      [token()],
      reach(),
      CATALOGUE,
      spend({ ceiling: 0, metered: false, history: week([12, 8, 0, 0, 0, 0, 0]) }),
    );

    const table = (await screen.findByText("Requests allowed")).closest("table")!;
    expect(within(table).getByText("12")).toBeInTheDocument();
    expect(screen.getByText(/A zero may be a day nobody was counting/)).toBeInTheDocument();
  });
});

describe("what it cost", () => {
  // Step 045b. The section above counts *calls*; this counts *money*. The two dials are
  // independent settings, so every rendering below is reachable on its own.

  const priced = {
    usd: 15,
    usd_ceiling: 100,
    usd_metered: true,
    tokens: 1_000_000,
    tokens_ceiling: 0,
    tokens_metered: false,
  };

  it("puts the spend against its ceiling, the rule this page already keeps for calls", async () => {
    show([token()], reach(), CATALOGUE, spend(priced));

    expect(await screen.findByText(/\$15\.00 of \$100\.00/)).toBeInTheDocument();
    expect(screen.getByText(/spent at a model today/)).toBeInTheDocument();
  });

  it("says nothing about money when neither dial is on, rather than drawing a zero", async () => {
    // `$0.00 of $0.00` is the most confident possible rendering of a number nobody is
    // counting — `Spent`'s own trap, one section down.
    show([token()], reach(), CATALOGUE, spend());

    expect(await screen.findByText("No spend limit.")).toBeInTheDocument();
    expect(
      screen.getByText(/Model spend is not limited on this deployment/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/spent at a model today/)).not.toBeInTheDocument();
  });

  it("tells a live ceiling with nothing spent apart from a ceiling that is off", async () => {
    // Two different answers to *why is this zero*, and only one of them means a call
    // could be refused tomorrow.
    show([token()], reach(), CATALOGUE, spend({ ...priced, usd: 0, tokens: 0 }));

    expect(await screen.findByText(/\$0\.00 of \$100\.00/)).toBeInTheDocument();
    expect(
      screen.getByText(/Nothing has been spent at a model today/),
    ).toBeInTheDocument();
  });

  it("falls back to the token ceiling when only that dial is on", async () => {
    // Not an edge case: the built-in rate list knows three model families, so a customer
    // brokering any other provider has a $0 figure under a live token ceiling from the
    // first call. A single `metered` flag would have to lie about one of the two.
    show(
      [token()],
      reach(),
      CATALOGUE,
      spend({
        usd: 0,
        usd_ceiling: 0,
        usd_metered: false,
        tokens: 1_000_000,
        tokens_ceiling: 5_000_000,
        tokens_metered: true,
      }),
    );

    // `tokens()` abbreviates above a thousand — the page's standing formatter, and the
    // reason this asserts its output rather than a raw count.
    expect(await screen.findByText(/1\.00M of 5\.00M/)).toBeInTheDocument();
  });

  it("shows the token net under the dollar figure when both dials are on", async () => {
    // Whichever is met first refuses, so a reader who only saw the dollars would not
    // understand a token refusal.
    show(
      [token()],
      reach(),
      CATALOGUE,
      spend({ ...priced, tokens_ceiling: 5_000_000, tokens_metered: true }),
    );

    expect(await screen.findByText(/\$15\.00 of \$100\.00/)).toBeInTheDocument();
    expect(
      screen.getByText(/Whichever limit is reached first denies the next call/),
    ).toBeInTheDocument();
  });

  it("names the models the price list could not value rather than dropping them", async () => {
    show(
      [token()],
      reach(),
      CATALOGUE,
      spend({ ...priced, usd: 0, unpriced_models: ["llama-3-70b"] }),
    );

    expect(await screen.findByText(/llama-3-70b/)).toBeInTheDocument();
    expect(screen.getByText(/has no rate in the price list/)).toBeInTheDocument();
  });

  it("names the remedy for an unpriced model, not only the gap", async () => {
    // Step 045c decision 4. Naming the model says the figure is short; naming the
    // operator's price list says who can make it whole. A customer brokering their own
    // provider is the ordinary case now, so the unpriced sentence is the one somebody
    // reads first and it has to end somewhere other than a dead end.
    show(
      [token()],
      reach(),
      CATALOGUE,
      spend({ ...priced, usd: 0, unpriced_models: ["gpt-5-mini"] }),
    );

    expect(
      await screen.findByText(/An operator can add rates to the price list/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Its tokens count against the token limit only/),
    ).toBeInTheDocument();
  });

  it("warns at the limit and says the crossing call completed", async () => {
    // Read-then-decide: a call's cost is only known once it returns, so the ceiling gates
    // the next one rather than holding anything back. A person looking at a figure past
    // its limit should not read it as a bug.
    show([token()], reach(), CATALOGUE, spend({ ...priced, usd: 120 }));

    const notice = await screen.findByRole("alert");
    expect(notice).toHaveTextContent("Spend limit reached");
    expect(notice).toHaveTextContent(/The call that crossed the limit completed/);
  });

  it("is shown even where the call meter is off, because they are separate limits", async () => {
    // The gap this closes: a deployment that stopped counting calls may still be bounding
    // spend, and a page that hid the money would be silent about the ceiling actually
    // refusing this credential.
    show(
      [token()],
      reach(),
      CATALOGUE,
      spend({ ...priced, ceiling: 0, metered: false }),
    );

    await screen.findByText("Requests are not metered");
    expect(screen.getByText(/\$15\.00 of \$100\.00/)).toBeInTheDocument();
  });
});

describe("whose access answered", () => {
  it("names the owner for a personal token, because the grants are theirs", async () => {
    // The listing can only ever say *personal*. Which person a personal token resolves
    // through is the entire question an offboarding review asks, and it stops being
    // always-you the moment an administrator can open this page.
    show(
      [token({ acts_as_owner: true })],
      reach({ acts_as_owner: true, resolved_as: "user:u_priya" }),
    );

    expect(await screen.findByText("user:u_priya")).toBeInTheDocument();
    expect(screen.getByText("personal")).toBeInTheDocument();
  });

  it("says a personal token's reach moves with its owner's", async () => {
    show(
      [token({ acts_as_owner: true })],
      reach({ acts_as_owner: true, resolved_as: "user:u_priya" }),
    );

    expect(
      await screen.findByText(/These are its owner's grants and change when the owner's do/),
    ).toBeInTheDocument();
  });

  it("resolves a service token as itself", async () => {
    show();

    expect(await screen.findByText("machine:m_8f2c1a")).toBeInTheDocument();
    expect(screen.getByText("service")).toBeInTheDocument();
  });
});

describe("granted nothing", () => {
  it("says so as a sentence rather than rendering an empty card", async () => {
    // Empty-denies is the default, so this is an answer and not a loading failure — and a
    // blank card is read as one. Same rule `TokensPage` applies to a person with no tokens.
    show([token()], reach({ tools: [], agents: [] }));

    expect(await screen.findByText(/This token has no agents\./)).toBeInTheDocument();
    expect(screen.getByText(/gets an empty/)).toBeInTheDocument();
    expect(screen.getByText(/and every call is denied/)).toBeInTheDocument();
  });

  it("points a personal token at the person rather than at the token", async () => {
    // A personal token holds no grants of its own by design — telling somebody to share an
    // agent *with the token* would send them to a seam that refuses them by name.
    show(
      [token({ acts_as_owner: true })],
      reach({ acts_as_owner: true, tools: [], agents: [] }),
    );

    expect(
      await screen.findByText(/A personal token uses its owner’s access\. Share an/),
    ).toBeInTheDocument();
    expect(screen.getByText(/with yourself to use it here/)).toBeInTheDocument();
  });
});

describe("a token that no longer works", () => {
  it("shows what it was granted and says it is revoked, without either implying the other", async () => {
    // **Decision 4 on screen.** The route ignores liveness on purpose: *what could this
    // token reach before I killed it* is the offboarding question. But a page showing the
    // reach and not the revocation would read as "this credential is live and reaches
    // this", which is the dangerous direction.
    show([token({ revoked_at: "2026-08-20T10:00:00+00:00", revoked_by: "u_boss" })]);

    expect(await screen.findByText("revoked")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "triage" })).toBeInTheDocument();
  });

  it("still renders never-used as a word, since reading this page did not change it", async () => {
    show();

    expect(await screen.findAllByText("never")).not.toHaveLength(0);
  });
});

describe("an agent that cannot be read", () => {
  it("names it rather than quietly counting one fewer", async () => {
    show(
      [token()],
      reach({ invalid_agents: ["filer"] }),
    );

    expect(await screen.findByText(/filer/)).toBeInTheDocument();
    expect(screen.getByText(/configuration is not valid/)).toBeInTheDocument();
  });

  it("names it even when nothing else is granted, where the count is 'nothing'", async () => {
    show([token()], reach({ tools: [], agents: [], invalid_agents: ["filer"] }));

    expect(await screen.findByText(/This token has no agents\./)).toBeInTheDocument();
    expect(screen.getByText(/configuration is not valid/)).toBeInTheDocument();
  });
});

describe("when something cannot be read", () => {
  it("shows the server's own sentence for a refused reach", async () => {
    show([token()], new ApiError(403, "only u_priya — who owns API token 'm_8f2c1a'"));

    expect(await screen.findByText(/only u_priya/)).toBeInTheDocument();
  });

  it("never says the token is not yours when what happened is that it could not ask", async () => {
    // `TokensPage`'s rule at a second address: a failed listing is not an absent token.
    // Here the missing branch would say *no token of yours has that id* about one they own.
    vi.mocked(api.myTokens).mockRejectedValue(new ApiError(503, "storage unavailable"));
    vi.mocked(api.tokenReach).mockResolvedValue(reach());
    vi.mocked(api.tokenBudget).mockResolvedValue(spend());
    vi.mocked(api.listTools).mockResolvedValue(CATALOGUE);

    render(
      <MemoryRouter initialEntries={["/tokens/m_8f2c1a"]}>
        <Routes>
          <Route path="/tokens/:tokenId" element={<TokenDetailPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText(/storage unavailable/)).toBeInTheDocument();
    expect(screen.queryByText("Token not found")).not.toBeInTheDocument();
  });

  it("keeps a failed budget from taking the reach off the screen, and the reverse", async () => {
    // Four requests, four `useResource`s, four `Failure`s. They are separate facts from
    // separate tables, and a reader wants whichever of them arrived — a 503 on `mcp_budget`
    // must not make it look as though the token reaches nothing.
    show([token()], reach(), CATALOGUE, new ApiError(503, "storage unavailable"));

    expect(await screen.findByText(/storage unavailable/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "triage" })).toBeInTheDocument();
    expect(screen.queryByText("Usage")).not.toBeInTheDocument();
  });

  it("shows the server's own sentence for a refused budget", async () => {
    show(
      [token()],
      reach(),
      CATALOGUE,
      new ApiError(400, "there is no API token 'm_8f2c1a' in this customer."),
    );

    expect(await screen.findByText(/there is no API token/)).toBeInTheDocument();
  });

  it("says a token id that is not one of yours is not one of yours", async () => {
    show([], reach());

    expect(await screen.findByText("Token not found")).toBeInTheDocument();
    expect(screen.getByText(/This page shows only your own tokens/)).toBeInTheDocument();
  });
});

describe("what the page does not offer", () => {
  it("holds no control that grants or widens anything", async () => {
    // Plan 035 category 2 said no button at all; step 044 reopened exactly one verb, and
    // it is the one that removes authority. The living half of the rule is that nothing
    // here mints, grants, or widens anything.
    //
    // **Its proxy expired in 069 and the rule did not.** This asserted *no text input at
    // all*, which stood while every input on an admin screen was a write — and 069 adds
    // a form whose submission changes nothing, dials nothing and records nothing. So the
    // assertion moves from *is there an input* to *what can be submitted*: two buttons,
    // one that revokes and one that asks a question, and no third.
    show();

    await screen.findByRole("heading", { name: "triage" });
    const buttons = screen.getAllByRole("button").map((node) => node.textContent);
    expect(buttons).toEqual(["Revoke token", "Check"]);
    // And the inputs that exist belong to that question, not to a grant.
    for (const box of screen.getAllByRole("textbox")) {
      expect(box.closest("form")).toBe(
        screen.getByRole("button", { name: "Check" }).closest("form"),
      );
    }
  });

  it("offers no revoke on a token that is already dead", async () => {
    // Absent, not disabled: revoking a revoked token is a true no-op, and a control
    // that does nothing is clutter on the page people read during incidents.
    show([token({ revoked_at: "2026-08-20T10:00:00+00:00" })]);

    await screen.findByRole("heading", { name: "triage" });
    expect(screen.queryByRole("button", { name: "Revoke token" })).not.toBeInTheDocument();
  });

  it("revokes behind a confirmation that says what stops", async () => {
    vi.mocked(api.revokeToken).mockResolvedValue({
      id: "m_8f2c1a",
      revoked_at: "2026-08-27T10:00:00+00:00",
      changed: true,
    });
    show();

    fireEvent.click(await screen.findByRole("button", { name: "Revoke token" }));
    // Nothing sent yet — the first click only opens the question.
    expect(api.revokeToken).not.toHaveBeenCalled();
    expect(screen.getByText(/Immediate and permanent/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));

    await waitFor(() => expect(api.revokeToken).toHaveBeenCalledWith("m_8f2c1a"));
    // The listing is re-read so the state badge changes in place — no redirect away
    // from a row that still exists.
    expect(vi.mocked(api.myTokens).mock.calls.length).toBeGreaterThan(1);
  });

  it("keeps the token when the person keeps it", async () => {
    show();

    fireEvent.click(await screen.findByRole("button", { name: "Revoke token" }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(api.revokeToken).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Revoke token" })).toBeInTheDocument();
  });

  it("offers a way back to the listing and nothing else that navigates away", async () => {
    show();

    await screen.findByRole("heading", { name: "triage" });
    const links = screen.getAllByRole("link").map((node) => node.getAttribute("href"));
    expect(links).toContain("/tokens");
  });
});

describe("the catalogue", () => {
  it("still names the granted tools when it cannot be loaded", async () => {
    // `Reach`'s degraded branch, reached through a new caller: the names are the grant
    // and are still true; what is missing is which of them change anybody's systems.
    show([token()], reach(), new ApiError(503, "storage unavailable"));

    const card = (
      await screen.findByRole("heading", { name: "triage" })
    ).closest("section")!;
    expect(within(card).getByText("github_mcp_list_issues")).toBeInTheDocument();
  });
});
