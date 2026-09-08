/** The Connections page, and the three-and-a-half states it exists to distinguish.
 *
 * Step 7b's deliverable. The plan's finding 6 is blunt about why the screen is the step
 * rather than a follow-on: ship the routes without it and the only caller is still an
 * engineer, this time with `curl` instead of the CLI, and *"an operator obtains and sees
 * every person's third-party token"* is untouched.
 *
 * Two of the assertions here are about what the page **does not** render, and those are
 * the ones worth keeping. A Connect button on a connector nobody configured is the
 * *"a control that exists and does nothing reads as a bug"* failure 10d already learned;
 * a silent success when the provider could not be told to revoke is a person believing a
 * token is dead when it is live.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return {
    ...actual,
    api: { listConnections: vi.fn(), startConnect: vi.fn(), disconnect: vi.fn() },
  };
});

import ConnectionsPage from "./ConnectionsPage";
import { api } from "../../lib/api";
import { CONSENT_MESSAGE } from "../../lib/consentWindow";
import type { ConnectionSummary } from "../../lib/types";

function row(overrides: Partial<ConnectionSummary> = {}): ConnectionSummary {
  return {
    connector_id: "jira",
    description: "Acme's internal Jira",
    state: "connectable",
    account_label: "",
    credential_kind: "",
    // Three instants, all null by default, because the default row is one nobody has
    // connected — and null is what "there is no connection to have a stamp" looks like
    // on all three. Required on the wire, nullable in value: 035f's distinction.
    expires_at: null,
    refresh_expires_at: null,
    updated_at: null,
    reconsent_reason: "",
    scopes: [],
    scope_notes: {},
    ...overrides,
  };
}

function show(rows: ConnectionSummary[], path = "/connections") {
  vi.mocked(api.listConnections).mockResolvedValue(rows);
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ConnectionsPage />
    </MemoryRouter>,
  );
}

/** A stand-in for the consent popup. jsdom's `window.open` returns null, which the page
 *  correctly reads as "blocked" — so a test that did not stub this would only ever
 *  exercise the fallback. */
function capturePopup() {
  const popup = { location: { href: "" }, closed: false, close: vi.fn() };
  vi.spyOn(window, "open").mockReturnValue(popup as unknown as Window);
  return popup;
}

/** Deliver the message the popup posts to its opener when the provider sends it back. */
function popupFinishes(outcome: { connected?: string; failed?: string }) {
  window.dispatchEvent(
    new MessageEvent("message", {
      origin: window.location.origin,
      data: {
        type: CONSENT_MESSAGE,
        connected: outcome.connected ?? "",
        failed: outcome.failed ?? "",
      },
    }),
  );
}

/** `window.location.assign`, for the blocked-popup fallback only. */
function captureNavigation() {
  const assign = vi.fn();
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { ...window.location, assign, origin: "http://localhost:3000" },
  });
  return assign;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("the three states", () => {
  it("offers Connect for a connector with a consent flow", async () => {
    show([row({ state: "connectable" })]);

    expect(await screen.findByRole("button", { name: "Connect" })).toBeTruthy();
  });

  it("shows who you are connected as, and offers Disconnect", async () => {
    show([
      row({ state: "connected", account_label: "priya@acme.com", credential_kind: "oauth" }),
    ]);

    expect(await screen.findByText(/Connected as priya@acme.com/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Disconnect" })).toBeTruthy();
  });

  it("renders NO button for a connector nobody has configured", async () => {
    // The assertion this whole state exists for. A Connect button here leads nowhere,
    // and somebody who presses it concludes the product is broken rather than that an
    // administrator has a task to do.
    show([row({ connector_id: "linear", state: "unavailable" })]);

    expect(
      await screen.findByText(/switched on personal sign-in/),
    ).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Connect" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Disconnect" })).toBeNull();
  });

  it("says to ask an administrator rather than leaving it blank", async () => {
    show([row({ state: "unavailable" })]);

    expect(
      await screen.findByText(/Ask an administrator to set it up/),
    ).toBeTruthy();
  });
});

describe("the fourth state, which is a half", () => {
  it("offers Reconnect and shows the provider's own reason", async () => {
    // Before this screen the first anybody heard of a revoked consent was a run failing.
    show([
      row({
        state: "reconnect",
        reconsent_reason: "Consent was withdrawn at Atlassian.",
      }),
    ]);

    expect(await screen.findByText(/Consent was withdrawn at Atlassian/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reconnect" })).toBeTruthy();
  });

  it("does not call it 'connected', because it cannot be used", async () => {
    show([row({ state: "reconnect", reconsent_reason: "The grant is gone." })]);

    await screen.findByRole("button", { name: "Reconnect" });
    expect(screen.queryByText(/^Connected as/)).toBeNull();
  });
});

describe("starting a flow", () => {
  it("sends the browser to the provider in a popup", async () => {
    // **The page must not unload.** Navigating away destroys this app's in-memory token,
    // so connecting an account signed people out — every time. See `consentWindow.ts`.
    const popup = capturePopup();
    vi.mocked(api.startConnect).mockResolvedValue({
      authorize_url: "https://auth.atlassian.com/authorize?client_id=abc&state=xyz",
    });
    show([row({ state: "connectable" })]);

    await userEvent.click(await screen.findByRole("button", { name: "Connect" }));

    await waitFor(() =>
      expect(popup.location.href).toBe(
        "https://auth.atlassian.com/authorize?client_id=abc&state=xyz",
      ),
    );
  });

  it("opens the window before asking the server, or the browser blocks it", async () => {
    // A browser only allows `window.open` inside the click a person actually made.
    // Waiting for the server first breaks that chain and the popup is blocked — so the
    // window is opened blank and pointed afterwards. Asserted by the ordering.
    capturePopup();
    let resolveUrl: (v: { authorize_url: string }) => void = () => {};
    vi.mocked(api.startConnect).mockReturnValue(
      new Promise((resolve) => {
        resolveUrl = resolve;
      }),
    );
    show([row({ state: "connectable" })]);

    await userEvent.click(await screen.findByRole("button", { name: "Connect" }));

    expect(window.open).toHaveBeenCalled();
    resolveUrl({ authorize_url: "https://x/authorize" });
  });

  it("falls back to navigating when the popup is blocked", async () => {
    // Strictly better than a Connect button that appears to do nothing. It costs the
    // session, which is the papercut the popup exists to avoid, and it still works.
    vi.spyOn(window, "open").mockReturnValue(null);
    const assign = captureNavigation();
    vi.mocked(api.startConnect).mockResolvedValue({ authorize_url: "https://x/authorize" });
    show([row({ state: "connectable" })]);

    await userEvent.click(await screen.findByRole("button", { name: "Connect" }));

    await waitFor(() => expect(assign).toHaveBeenCalledWith("https://x/authorize"));
  });

  it("asks the server to bring the browser back here", async () => {
    capturePopup();
    vi.mocked(api.startConnect).mockResolvedValue({ authorize_url: "https://x/authorize" });
    show([row({ state: "connectable" })]);

    await userEvent.click(await screen.findByRole("button", { name: "Connect" }));

    expect(api.startConnect).toHaveBeenCalledWith("jira", "/connections");
  });

  it("announces the connection and reloads when the popup reports back", async () => {
    const popup = capturePopup();
    vi.mocked(api.startConnect).mockResolvedValue({ authorize_url: "https://x/authorize" });
    show([row({ state: "connectable" })]);

    await userEvent.click(await screen.findByRole("button", { name: "Connect" }));
    await waitFor(() => expect(popup.location.href).toBe("https://x/authorize"));
    popupFinishes({ connected: "jira" });

    expect(await screen.findByText("jira is connected")).toBeTruthy();
    await waitFor(() => expect(api.listConnections).toHaveBeenCalledTimes(2));
  });

  it("says nothing when somebody closes the popup without deciding", async () => {
    // The ordinary way this ends — they change their mind at the provider's screen. Any
    // message here would be inventing an event that did not happen.
    const popup = capturePopup();
    vi.mocked(api.startConnect).mockResolvedValue({ authorize_url: "https://x/authorize" });
    show([row({ state: "connectable" })]);

    await userEvent.click(await screen.findByRole("button", { name: "Connect" }));
    await waitFor(() => expect(popup.location.href).toBe("https://x/authorize"));
    popup.closed = true;

    // And the button comes back, rather than spinning forever — which is the failure
    // people report as "it hung".
    expect(await screen.findByRole("button", { name: "Connect" })).toBeTruthy();
    expect(screen.queryByText(/is connected/)).toBeNull();
  });

  it("ignores a message from the provider's own origin", async () => {
    // The popup visits a **third party** in the middle of this, and that third party can
    // post to its opener. A message whose origin is not ours is exactly that.
    const popup = capturePopup();
    vi.mocked(api.startConnect).mockResolvedValue({ authorize_url: "https://x/authorize" });
    show([row({ state: "connectable" })]);

    await userEvent.click(await screen.findByRole("button", { name: "Connect" }));
    await waitFor(() => expect(popup.location.href).toBe("https://x/authorize"));

    window.dispatchEvent(
      new MessageEvent("message", {
        origin: "https://auth.atlassian.com",
        data: { type: CONSENT_MESSAGE, connected: "jira", failed: "" },
      }),
    );

    await waitFor(() => expect(screen.queryByText("jira is connected")).toBeNull());
  });

  it("shows the scopes before the button that agrees to them", async () => {
    // The alternative is that the first time somebody learns what they are agreeing to
    // is on a third party's page, at the moment they are trying to get past it.
    show([row({ state: "connectable", scopes: ["read:jira-work", "offline_access"] })]);

    expect(
      await screen.findByText(/jira will be asked for: read:jira-work, offline_access/),
    ).toBeTruthy();
  });

  it("reports a refusal rather than silently doing nothing", async () => {
    capturePopup();
    vi.mocked(api.startConnect).mockRejectedValue(
      new Error("connector 'jira' has no consent flow configured"),
    );
    show([row({ state: "connectable" })]);

    await userEvent.click(await screen.findByRole("button", { name: "Connect" }));

    expect(await screen.findByText(/no consent flow configured/)).toBeTruthy();
  });
});

describe("coming back from the provider", () => {
  it("says the connection worked and that nobody here saw the credential", async () => {
    show([row({ state: "connected", account_label: "priya@acme.com" })], "/connections?connected=jira");

    expect(await screen.findByText("jira is connected")).toBeTruthy();
    expect(screen.getByText(/Nobody here saw the credential/)).toBeTruthy();
  });

  it("renders the server's own sentence when it did not finish", async () => {
    // Covers Deny, an expired link, and a `state` we never issued. The page must not
    // guess which — two of those are ordinary and one is somebody probing.
    show(
      [row({ state: "connectable" })],
      "/connections?failed=this+sign-in+link+is+not+one+we+issued",
    );

    expect(
      await screen.findByText(/this sign-in link is not one we issued/),
    ).toBeTruthy();
    expect(screen.getByText(/Nothing was stored/)).toBeTruthy();
  });

  it("clears the outcome so a reload does not re-announce it", async () => {
    show([row({ state: "connected" })], "/connections?connected=jira");

    await userEvent.click(await screen.findByRole("button", { name: "Dismiss" }));

    await waitFor(() => expect(screen.queryByText("jira is connected")).toBeNull());
  });
});

describe("disconnecting", () => {
  it("reloads the list so the row becomes Connect again", async () => {
    vi.mocked(api.disconnect).mockResolvedValue({
      disconnected: true,
      revoked_upstream: true,
    });
    vi.mocked(api.listConnections)
      .mockResolvedValueOnce([row({ state: "connected", account_label: "p@acme.com" })])
      .mockResolvedValue([row({ state: "connectable" })]);

    render(
      <MemoryRouter initialEntries={["/connections"]}>
        <ConnectionsPage />
      </MemoryRouter>,
    );

    await userEvent.click(await screen.findByRole("button", { name: "Disconnect" }));

    expect(await screen.findByRole("button", { name: "Connect" })).toBeTruthy();
  });

  it("says so when the provider could not be told, rather than reporting success", async () => {
    // Decision 12: the local delete happens either way, so a provider outage cannot trap
    // somebody in a connection they asked to end. The cost is that the token may still be
    // live — and a page that stayed quiet about it would be the reason they believe
    // otherwise.
    vi.mocked(api.disconnect).mockResolvedValue({
      disconnected: true,
      revoked_upstream: false,
    });
    show([row({ state: "connected", account_label: "p@acme.com" })]);

    await userEvent.click(await screen.findByRole("button", { name: "Disconnect" }));

    expect(await screen.findByText(/may still be live there/)).toBeTruthy();
  });

  it("stays quiet when there was nobody to tell", async () => {
    // `null`, not `false`. A pasted credential can be revoked by nobody but its owner,
    // and warning about it would be alarming somebody about the normal case.
    vi.mocked(api.disconnect).mockResolvedValue({
      disconnected: true,
      revoked_upstream: null,
    });
    show([row({ state: "connected", credential_kind: "static" })]);

    await userEvent.click(await screen.findByRole("button", { name: "Disconnect" }));

    await waitFor(() => expect(api.listConnections).toHaveBeenCalledTimes(2));
    expect(screen.queryByText(/may still be live/)).toBeNull();
  });
});

describe("is there anything behind this when it lapses", () => {
  // 035f. The three fields are asserted together because they only mean anything
  // together: `expires_at` on its own is noise on the rows that renew and silence on
  // the rows that do not.

  const FUTURE = "2099-03-04T10:00:00Z";
  const PAST = "2020-03-04T10:00:00Z";

  it("says a pasted credential expires and that nothing will renew it", async () => {
    // The case the schema comment says `expires_at` exists for: a credential with no
    // refresh behind it. Before 035f the page did not read the field at all.
    show([
      row({
        state: "connected",
        credential_kind: "static",
        account_label: "svc@acme.com",
        expires_at: FUTURE,
      }),
    ]);

    expect(await screen.findByText(/This credential expires on/)).toBeTruthy();
    expect(screen.getByText(/Nothing here can renew it/)).toBeTruthy();
  });

  it("says a pasted credential has already expired, correcting the row above it", async () => {
    // `describe()` still says "Connected as svc@acme.com", which is true of the row and
    // useless to somebody whose agent is failing. This is the half that says why.
    show([
      row({
        state: "connected",
        credential_kind: "static",
        account_label: "svc@acme.com",
        expires_at: PAST,
      }),
    ]);

    expect(await screen.findByText(/This credential expired on/)).toBeTruthy();
    expect(screen.getByText(/Connected as svc@acme.com/)).toBeTruthy();
  });

  it("says NOTHING about an OAuth access token that has expired", async () => {
    // **The assertion this whole helper exists for, and the one the obvious fix fails.**
    // A healthy OAuth connection is renewed at the start of a run, so its `expires_at`
    // sits in the past for most of the time it exists. A page that rendered the field
    // wherever it was set would tell the majority of healthy connections they had
    // expired and invite somebody to reconnect one that is fine.
    show([
      row({
        state: "connected",
        credential_kind: "oauth",
        account_label: "priya@acme.com",
        expires_at: PAST,
      }),
    ]);

    await screen.findByText(/Connected as priya@acme.com/);
    expect(screen.queryByText(/expired on/)).toBeNull();
    expect(screen.queryByText(/expires on/)).toBeNull();
  });

  it("says when the connection itself lapses, which renewing cannot fix", async () => {
    // Migration 024's own argument for the column: without it, "this will need
    // re-consenting" cannot be predicted at all, only discovered by a run failing.
    show([
      row({
        state: "connected",
        credential_kind: "oauth",
        account_label: "priya@acme.com",
        expires_at: PAST,
        refresh_expires_at: FUTURE,
      }),
    ]);

    expect(await screen.findByText(/This connection lapses on/)).toBeTruthy();
    expect(screen.getByText(/you will need to connect it again/)).toBeTruthy();
  });

  it("says nothing when the provider never said, rather than promising it will not lapse", async () => {
    // Null means "the provider did not volunteer a refresh lifetime" — most do not — and
    // it is also what a connection carrying no refresh token at all looks like until the
    // next refresh turns it into `reconnect`. Neither is "this will not lapse".
    show([
      row({
        state: "connected",
        credential_kind: "oauth",
        account_label: "priya@acme.com",
        refresh_expires_at: null,
      }),
    ]);

    await screen.findByText(/Connected as priya@acme.com/);
    expect(screen.queryByText(/lapses on/)).toBeNull();
  });

  it("says nothing about a lapse on a row that is already broken", async () => {
    // `reconnect` already carries the provider's reason. A second sentence about a future
    // lapse is noise on top of a fact that has already happened.
    show([
      row({
        state: "reconnect",
        credential_kind: "oauth",
        reconsent_reason: "Consent was withdrawn at Atlassian.",
        refresh_expires_at: "2099-01-01T00:00:00Z",
      }),
    ]);

    await screen.findByRole("button", { name: "Reconnect" });
    expect(screen.queryByText(/lapses on/)).toBeNull();
  });

  it("says when the credential last changed", async () => {
    // Migration 013's question — "when did this last change" is the first one asked when
    // somebody's agent starts failing — reaching a browser for the first time.
    show([
      row({
        state: "connected",
        credential_kind: "oauth",
        account_label: "priya@acme.com",
        updated_at: "2026-08-01T09:30:00Z",
      }),
    ]);

    expect(await screen.findByText(/Last changed/)).toBeTruthy();
  });

  it("says nothing about a change on a connector nobody has connected", async () => {
    show([row({ state: "connectable", updated_at: null })]);

    await screen.findByRole("button", { name: "Connect" });
    expect(screen.queryByText(/Last changed/)).toBeNull();
  });
});

describe("a lapse that has already happened, and a year that has to be shown", () => {
  // Two rendering defects found by testing 035f rather than by reading it, both on the
  // row that most needs the sentence to be right.

  it("uses the PAST tense for a refresh token that already lapsed", async () => {
    // **Reachable, and it is the case the field exists for.** A connection nobody has
    // run for six months has a lapsed refresh token, an empty `reconsent_reason` —
    // because nothing has tried and failed yet — and a `state` of `connected`. The first
    // version of this said "lapses on 1 January 2020. It renews itself until then",
    // which is a future-tense promise about something that has already happened, on the
    // connection whose next run is going to fail.
    show([
      row({
        state: "connected",
        credential_kind: "oauth",
        account_label: "priya@acme.com",
        refresh_expires_at: "2020-01-01T00:00:00Z",
      }),
    ]);

    expect(await screen.findByText(/This connection lapsed on/)).toBeTruthy();
    expect(screen.getByText(/the next agent that needs it will fail/)).toBeTruthy();
    expect(screen.queryByText(/renews itself until then/)).toBeNull();
  });

  it("shows the year, so a lapse five years old is not read as last December", async () => {
    // `on()` omits the year — it was written for run listings, where everything is
    // recent — so a 2020 expiry and a 2099 one both rendered as `Dec 31` and `Mar 4`.
    // On a screen about access that is the difference between *act now* and *nothing
    // to do*, so these three stamps use `day()` instead.
    show([
      row({
        state: "connected",
        credential_kind: "static",
        account_label: "svc@acme.com",
        expires_at: "2020-06-15T12:00:00Z",
        updated_at: "2019-03-02T09:00:00Z",
      }),
    ]);

    await screen.findByText(/This credential expired on/);
    expect(screen.getByText(/This credential expired on.*2020/)).toBeTruthy();
    expect(screen.getByText(/Last changed.*2019/)).toBeTruthy();
  });

  it("does not raise an alarm about a stamp it cannot parse", async () => {
    // The quieter of the two wrong answers. A garbage instant is a server or migration
    // problem, and rendering it as *expired* would send somebody to reconnect a
    // credential that is probably fine.
    show([
      row({
        state: "connected",
        credential_kind: "static",
        account_label: "svc@acme.com",
        expires_at: "not-a-date",
      }),
    ]);

    expect(await screen.findByText(/This credential expires on not-a-date/)).toBeTruthy();
    expect(screen.queryByText(/expired on/)).toBeNull();
  });
});

describe("the full grid of what a row may say about lapsing", () => {
  // One test per cell, because the whole of 035f's judgement is which cells are silent.
  // `expires_at` is set in the past on every OAuth row here: that is the *resting state*
  // of a healthy renewing connection, and it must never produce a sentence.

  const PAST = "2020-01-01T00:00:00Z";
  const FUTURE = "2099-01-01T00:00:00Z";

  const cells: Array<[string, Partial<ConnectionSummary>, RegExp | null]> = [
    ["static with a future expiry", { credential_kind: "static", expires_at: FUTURE }, /credential expires on/],
    ["static with a past expiry", { credential_kind: "static", expires_at: PAST }, /credential expired on/],
    ["static with no expiry", { credential_kind: "static" }, null],
    ["oauth with a past access token", { credential_kind: "oauth", expires_at: PAST }, null],
    ["oauth with a future access token", { credential_kind: "oauth", expires_at: FUTURE }, null],
    ["oauth with a future lapse", { credential_kind: "oauth", expires_at: PAST, refresh_expires_at: FUTURE }, /connection lapses on/],
    ["oauth with a past lapse", { credential_kind: "oauth", expires_at: PAST, refresh_expires_at: PAST }, /connection lapsed on/],
    ["oauth with neither", { credential_kind: "oauth" }, null],
  ];

  for (const [name, fields, expected] of cells) {
    it(`${name}: ${expected ? "says so" : "says nothing"}`, async () => {
      show([row({ state: "connected", account_label: "p@acme.com", ...fields })]);
      await screen.findByText(/Connected as p@acme.com/);

      if (expected) {
        expect(screen.getByText(expected)).toBeTruthy();
      } else {
        expect(screen.queryByText(/expires on|expired on|lapses on|lapsed on/)).toBeNull();
      }
    });
  }

  it("says nothing on any state that is not connected, whatever the row carries", async () => {
    // A `connectable` or `unavailable` row has no credential and no stamps; a `reconnect`
    // row has both and already carries the provider's reason, and a second sentence about
    // a future lapse on top of a failure that has happened is noise.
    for (const state of ["connectable", "reconnect", "unavailable"] as const) {
      const { unmount } = show([
        row({
          state,
          credential_kind: "oauth",
          reconsent_reason: state === "reconnect" ? "The grant is gone." : "",
          refresh_expires_at: "2099-01-01T00:00:00Z",
          expires_at: "2020-01-01T00:00:00Z",
        }),
      ]);
      // Waited on the badge, which is the one thing each of the three states puts on
      // screen unconditionally — 093 moved the state out of `describe()`'s sentence and
      // into `status()`, so the sentences no longer share an opening to wait on.
      await screen.findByText(
        {
          connectable: "Not connected",
          reconnect: "Needs reconnecting",
          unavailable: "Not available yet",
        }[state],
      );
      expect(screen.queryByText(/lapses on|lapsed on|expires on|expired on/)).toBeNull();
      unmount();
    }
  });
});

describe("what the connector asks for, and what that is not", () => {
  // 035f, trap 1. `scopes` is the OAuth **application's** configured ask; what a person
  // granted is stored nowhere. Every assertion here is about which question the sentence
  // is answering.

  it("shows the scopes before the Reconnect button too", async () => {
    // The old gate named `connectable` where it meant *there is a button here that sends
    // somebody to a consent screen*. `reconnect` has one, and had no scope line.
    show([
      row({
        state: "reconnect",
        reconsent_reason: "The grant is gone.",
        scopes: ["read:jira-work", "offline_access"],
      }),
    ]);

    expect(
      await screen.findByText(/jira will be asked for: read:jira-work, offline_access/),
    ).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reconnect" })).toBeTruthy();
  });

  it("tells a connected person the ask is not a record of what they granted", async () => {
    // **The sentence the one-line fix would have shipped without.** An administrator who
    // widens the app's scopes after somebody connected would otherwise have this page
    // claim their live credential carries scopes it never had.
    show([
      row({
        state: "connected",
        credential_kind: "oauth",
        account_label: "priya@acme.com",
        scopes: ["read:jira-work", "write:jira-work"],
      }),
    ]);

    expect(await screen.findByText(/jira asks for: read:jira-work, write:jira-work/)).toBeTruthy();
    expect(
      screen.getByText(/not a record of what this connection was granted/),
    ).toBeTruthy();
  });

  it("says nothing about scopes beside a credential an administrator pasted in", async () => {
    // The other half the one-liner gets wrong. A static credential never met a consent
    // screen, and the connector may have an OAuth application configured regardless — so
    // `scopes` is non-empty on this row and describes a flow this credential did not take.
    show([
      row({
        state: "connected",
        credential_kind: "static",
        account_label: "svc@acme.com",
        scopes: ["read:jira-work"],
      }),
    ]);

    await screen.findByText(/added by an administrator/);
    expect(screen.queryByText(/asks for/)).toBeNull();
    expect(screen.queryByText(/will be asked for/)).toBeNull();
  });

  it("says nothing when there is no consent flow to ask anything", async () => {
    show([row({ connector_id: "linear", state: "unavailable", scopes: [] })]);

    await screen.findByText(/switched on personal sign-in/);
    expect(screen.queryByText(/asked for/)).toBeNull();
  });
});

describe("what the page never renders", () => {
  it("marks a credential an administrator pasted in", async () => {
    // Not decoration: a static credential is one an operator held, and it cannot renew
    // itself. Both are things the person reading would want to know.
    show([row({ state: "connected", credential_kind: "static", account_label: "x" })]);

    expect(await screen.findByText(/added by an administrator/)).toBeTruthy();
  });

  it("shows an empty list as an answer rather than a fault", async () => {
    show([]);

    expect(await screen.findByText("Nothing to connect yet")).toBeTruthy();
    expect(screen.queryByText(/error/i)).toBeNull();
  });

  it("reads the list once and does not poll", async () => {
    // The convention every screen in this app is asserted against. Nothing added in 035f
    // is a countdown, so nothing here has a reason to tick: an expiry is an instant the
    // server already decided, and re-fetching it every few seconds would be this page
    // inventing a clock.
    show([row({ state: "connected", credential_kind: "oauth", account_label: "p@acme.com" })]);
    await screen.findByText(/Connected as p@acme.com/);

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(api.listConnections).toHaveBeenCalledTimes(1);
  });

  it("names no principal anywhere, because this page is only ever about you", async () => {
    const { container } = show([
      row({ state: "connected", account_label: "priya@acme.com", credential_kind: "oauth" }),
    ]);

    await screen.findByText(/Connected as priya@acme.com/);
    // There is no route that answers about anybody else and no field carrying one. If a
    // principal id ever appears here it arrived from somewhere this page should not be
    // reading, which is the mistake worth failing on.
    expect(container.textContent).not.toMatch(/user:u_/);
  });
});

describe("what a scope permits — migration 051", () => {
  const NOTES = {
    "write:jira-work": {
      name: "Create and edit issues",
      description: "Open, edit and transition issues — anything you could do yourself.",
      access: "write" as const,
    },
    "read:jira-work": {
      name: "Read issues and projects",
      description: "See issues you already have access to. Changes nothing.",
      access: "read" as const,
    },
  };

  it("says what a scope permits, before the button that grants it", async () => {
    // The whole point of the column. Without it this screen asks somebody who is not an
    // administrator to grant `write:jira-work` with nothing anywhere saying what it means.
    show([
      row({
        state: "connectable",
        scopes: ["read:jira-work", "write:jira-work"],
        scope_notes: NOTES,
      }),
    ]);
    expect(await screen.findByText("Create and edit issues")).toBeInTheDocument();
    expect(screen.getByText("Read issues and projects")).toBeInTheDocument();
    expect(screen.getByText(/anything you could do yourself/)).toBeInTheDocument();
  });

  it("marks a write scope with the same tag the catalogue uses", async () => {
    show([
      row({ state: "connectable", scopes: ["write:jira-work"], scope_notes: NOTES }),
    ]);
    expect(await screen.findByText("write")).toBeInTheDocument();
  });

  it("renders a scope with no note as it always did, rather than inventing one", async () => {
    // `offline_access` is bookkeeping with nothing to say to a person, and a sentence
    // invented for it would be describing somebody else's permission from a guess.
    show([
      row({
        state: "connectable",
        scopes: ["read:jira-work", "offline_access"],
        scope_notes: { "read:jira-work": NOTES["read:jira-work"] },
      }),
    ]);
    expect(await screen.findByText(/will be asked for/)).toHaveTextContent(
      "offline_access",
    );
    expect(screen.getByText("Read issues and projects")).toBeInTheDocument();
    expect(screen.queryByText(/offline_access —/)).not.toBeInTheDocument();
  });

  it("does not describe scopes beside a connected row", async () => {
    // Beside a live credential this would describe what the app asks for *now* rather
    // than what this person granted — the trap `asks` already carries a caveat for, and
    // a paragraph of prose cannot carry it legibly.
    show([
      row({
        state: "connected",
        credential_kind: "oauth",
        account_label: "priya@acme.com",
        scopes: ["write:jira-work"],
        scope_notes: NOTES,
      }),
    ]);
    await screen.findByText(/asks for/);
    expect(screen.queryByText("Create and edit issues")).not.toBeInTheDocument();
  });

  it("renders nothing extra when a connector has no prose at all", async () => {
    show([row({ state: "connectable", scopes: ["read:jira-work"], scope_notes: {} })]);
    expect(await screen.findByText(/will be asked for/)).toBeInTheDocument();
    expect(document.querySelector(".scope-notes")).toBeNull();
  });
});
