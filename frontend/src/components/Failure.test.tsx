/** The error path every page shares, tested once instead of greped-at from each page.
 *
 * Two of its branches are decisions somebody argued about, and those are what is pinned:
 *
 *   - **404 must not guess.** It is also "you have no grant on this", deliberately
 *     indistinguishable, so the server's sentence has to be the whole answer — a helpful
 *     "ask an administrator for access" would leak exactly what the 404 protects.
 *   - **403 must say that signing in again will not help.** Authenticated and still not
 *     allowed is a fact for an administrator, and a UI that bounced to the provider
 *     would loop on a login that cannot fix it.
 *
 * And one branch is an absence: `NotSignedIn` renders nothing, because the gate is about
 * to take over and a flashed message would be read by somebody already on their way out.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import Failure from "./Failure";
import { ApiError, NotSignedIn } from "../lib/api";

describe("the branches that carry a decision", () => {
  it("renders nothing at all for NotSignedIn", () => {
    const { container } = render(<Failure error={new NotSignedIn("not signed in")} />);

    expect(container).toBeEmptyDOMElement();
  });

  it("gives a 404 the server's sentence and nothing helpful beside it", () => {
    render(<Failure error={new ApiError(404, "no agent named 'payroll-bot'")} />);

    expect(screen.getByText("Not here")).toBeInTheDocument();
    expect(screen.getByText("no agent named 'payroll-bot'")).toBeInTheDocument();
    // The anti-enumeration property lives in what is NOT said: no hint that access
    // might exist to ask for.
    expect(screen.queryByText(/administrator/i)).not.toBeInTheDocument();
  });

  it("tells a 403 that signing in again will not change it", () => {
    render(<Failure error={new ApiError(403, "your account does not hold 'admin'")} />);

    expect(screen.getByText("your account does not hold 'admin'")).toBeInTheDocument();
    expect(screen.getByText(/Signing in again will not change this/)).toBeInTheDocument();
  });
});

describe("the rest of the map", () => {
  it("says what a 422 means and lets the server say what happened", () => {
    // Step 066. This read "This agent's configuration is not valid" — one caller's case
    // promoted to the general one, written when the only 422 a page could meet was a
    // stored agent config that no longer validated. It is a general status again, and
    // the agent sentence still arrives when that is what happened, because
    // `routes_agents.py` writes it into `detail`.
    render(<Failure error={new ApiError(422, "scope names a tool it is not granted")} />);

    expect(
      screen.getByText("The server would not accept that request"),
    ).toBeInTheDocument();
    expect(screen.getByText("scope names a tool it is not granted")).toBeInTheDocument();
  });

  it("points a reader at the query string, which is where a 422 now comes from", () => {
    // The reason this wording could change at all: 066 puts log filters in the URL, so
    // `?decision=banana` is a 422 somebody can produce by typing. The old sentence told
    // them an agent was broken.
    render(<Failure error={new ApiError(422, "decision: unexpected value")} />);

    expect(screen.getByText(/check the part after the/)).toBeInTheDocument();
  });

  it("says nothing was lost on a 503", () => {
    render(<Failure error={new ApiError(503, "the database is not reachable")} />);

    expect(screen.getByText(/Nothing has been lost/)).toBeInTheDocument();
  });

  it("carries an unmapped status in its title rather than swallowing it", () => {
    render(<Failure error={new ApiError(500, "something broke")} />);

    expect(screen.getByText("The server refused (500)")).toBeInTheDocument();
    expect(screen.getByText("something broke")).toBeInTheDocument();
  });

  it("renders a transport failure as its own message", () => {
    render(<Failure error={new TypeError("Failed to fetch")} />);

    expect(screen.getByText("Could not reach the server")).toBeInTheDocument();
    expect(screen.getByText("Failed to fetch")).toBeInTheDocument();
  });
});
