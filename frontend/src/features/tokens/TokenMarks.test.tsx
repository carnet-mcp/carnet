/** The three marks, and the orderings inside them that are decisions.
 *
 * `State` resolves revoked → expired → live, and the first arrow matters: a token
 * revoked *before* its expiry date is a decision somebody made, and showing "expired"
 * would erase the actor from the one place their act is visible. `Moment` renders a null
 * as a word because three nulls on a token row mean three different things and a blank
 * cell reads as a field the server failed to send. `Kind` is a word and a colour and
 * never a colour alone.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Kind, Moment, State } from "./TokenMarks";
import type { OwnedToken } from "../../lib/types";

function token(overrides: Partial<OwnedToken> = {}): OwnedToken {
  return {
    id: "tok_1234",
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

describe("Kind", () => {
  it("marks a personal token with its consequence, not just a word", () => {
    render(<Kind token={token({ acts_as_owner: true })} />);

    expect(screen.getByText("personal")).toBeInTheDocument();
    expect(screen.getByText("you, capped at user")).toBeInTheDocument();
  });

  it("marks a service token as bounded by its own grants", () => {
    render(<Kind token={token()} />);

    expect(screen.getByText("service")).toBeInTheDocument();
    expect(screen.getByText("only its own grants")).toBeInTheDocument();
  });
});

describe("Moment", () => {
  it("renders a null as the caller's word for it, not a blank", () => {
    render(<Moment iso={null} absent="never used" />);

    expect(screen.getByText("never used")).toBeInTheDocument();
  });

  it("renders an instant as an instant", () => {
    render(<Moment iso="2026-08-01T09:00:00+00:00" absent="never" />);

    expect(screen.queryByText("never")).not.toBeInTheDocument();
  });
});

describe("State", () => {
  it("says revoked, and by whom — even when the expiry date has also passed", () => {
    // The ordering under test: revocation is the deliberate act and wins over expiry.
    render(
      <State
        token={token({
          revoked_at: "2026-08-02T10:00:00+00:00",
          revoked_by: "user:u_admin",
          expires_at: "2020-01-01T00:00:00+00:00",
        })}
      />,
    );

    expect(screen.getByText("revoked")).toBeInTheDocument();
    expect(screen.getByText(/by user:u_admin/)).toBeInTheDocument();
    expect(screen.queryByText("expired")).not.toBeInTheDocument();
  });

  it("derives expired from an instant already on the row", () => {
    render(<State token={token({ expires_at: "2020-01-01T00:00:00+00:00" })} />);

    expect(screen.getByText("expired")).toBeInTheDocument();
  });

  it("calls everything else live — including a future expiry", () => {
    render(<State token={token({ expires_at: "2099-01-01T00:00:00+00:00" })} />);

    expect(screen.getByText("live")).toBeInTheDocument();
  });
});
