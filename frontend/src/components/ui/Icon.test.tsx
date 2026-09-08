/** The glyphs, tested as a set rather than one by one.
 *
 * `PATHS` is a `Record<IconName, string[]>`, so the compiler already refuses a name with
 * no drawing. What it cannot refuse is an *empty* drawing — `[]` typechecks and renders
 * an invisible icon — and it cannot see the two accessibility decisions the file's own
 * docstring argues: every icon is `aria-hidden` (it always sits beside its label), and
 * every icon is stroked with `currentColor` so the row's text colour is the icon's.
 */

import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Icon, type IconName } from "./Icon";

// A `Record<IconName, …>` rather than an array, so the compiler refuses this test the
// moment a name is added to the type and not here — an array would just quietly stop
// being the full set.
const ALL: Record<IconName, 0> = {
  agents: 0,
  connections: 0,
  tokens: 0,
  overview: 0,
  admin: 0,
  door: 0,
  denied: 0,
  groups: 0,
  connectors: 0,
  signout: 0,
  collapse: 0,
  expand: 0,
  plus: 0,
  check: 0,
  copy: 0,
  info: 0,
  warn: 0,
  alert: 0,
  inbox: 0,
};
const NAMES = Object.keys(ALL) as IconName[];

describe("every icon", () => {
  it.each(NAMES)("'%s' draws at least one path, hidden from the reader", (name) => {
    const { container } = render(<Icon name={name} />);

    const svg = container.querySelector("svg");
    expect(svg).not.toBeNull();
    expect(svg).toHaveAttribute("aria-hidden", "true");
    expect(svg?.querySelectorAll("path").length).toBeGreaterThan(0);
    // Whatever colour its text is — the property that lets an active nav row tint its
    // icon without this file knowing the palette.
    expect(svg).toHaveAttribute("stroke", "currentColor");
  });

  it("takes its size from the caller", () => {
    const { container } = render(<Icon name="plus" size={24} />);

    expect(container.querySelector("svg")).toHaveAttribute("width", "24");
  });
});
