/** The property the app never had: a render-time throw becomes a sentence.
 *
 * Before this component, any child that threw unmounted the React root and the person
 * got a blank tab — found by 023b's testing pass at the worst possible instant, with a
 * show-once secret on screen. These tests pin the contract; the AppShell suite pins the
 * placement.
 */

import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Boundary from "./Boundary";

function Bomb({ error }: { error: unknown }): never {
  throw error;
}

beforeEach(() => {
  // React reports every caught render error through console.error. That reporting is
  // its contract, not a defect in these tests — silence it rather than assert on it.
  vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("Boundary", () => {
  it("renders its children when nothing is wrong", () => {
    render(
      <Boundary>
        <p>the page</p>
      </Boundary>,
    );

    expect(screen.getByText("the page")).toBeInTheDocument();
  });

  it("turns a child's render throw into an alert carrying the error's own words", () => {
    render(
      <Boundary>
        <Bomb error={new Error("the card is broken")} />
      </Boundary>,
    );

    // `role="alert"` so a screen reader is told rather than left to find it — the same
    // argument as Notice's `bad` tone, which this is.
    expect(screen.getByRole("alert")).toHaveTextContent("This page failed to render");
    expect(screen.getByText("the card is broken")).toBeInTheDocument();
    // The sentence a person acts on: their data is intact and the nav still works.
    expect(screen.getByText(/Nothing has been lost/)).toBeInTheDocument();
  });

  it("survives a thrown value that is not an Error, including null", () => {
    // `throw null` is legal JavaScript, and a boundary that read `.message` off it
    // would itself throw — the one failure this component must never have.
    render(
      <Boundary>
        <Bomb error={null} />
      </Boundary>,
    );

    expect(screen.getByRole("alert")).toHaveTextContent("This page failed to render");
    expect(screen.getByText("null")).toBeInTheDocument();
  });
});
