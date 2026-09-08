/** The chart primitives, tested where they can be wrong in a way nobody sees.
 *
 * A chart fails quietly. A bar drawn from the wrong number still looks like a bar, and
 * the reader has no way to tell — which is why the assertions here are about *geometry
 * and arithmetic* rather than about whether an SVG rendered. Four things can go wrong
 * silently and each has a test:
 *
 *   - **a segment drawn from the wrong value**, which a screenshot cannot disprove
 *   - **a null joined across as a zero**, which invents a measurement on a day nothing
 *     was timed — the one thing `LatencyDay`'s nullability exists to prevent
 *   - **a legend that goes missing**, leaving identity to colour alone
 *   - **a mark with no `<title>`**, which is the hover tooltip *and* what a screen
 *     reader announces
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { BarStack, Figure, HBar, Meter, TrendLine } from "./charts";
import type { Series } from "./charts";

/** The `<title>` of every mark, in document order.
 *
 *  Read off the DOM rather than through `getByTitle`, which only matches a `<title>`
 *  that is a *direct* child of the `<svg>`. These are nested one level down, inside the
 *  `<rect>` or `<circle>` they describe, which is exactly where they have to be for a
 *  browser to show them on hover over that mark. */
const titles = (container: HTMLElement) =>
  [...container.querySelectorAll("title")].map((node) => node.textContent);

const TWO: Series[] = [
  { key: "a", label: "Alpha", color: "var(--chart-1)" },
  { key: "b", label: "Beta", color: "var(--chart-2)" },
];

describe("BarStack", () => {
  it("gives every segment a title carrying its day and its number", () => {
    const { container } = render(
      <BarStack
        rows={[{ day: "2026-08-01", a: 3, b: 1 }]}
        series={TWO}
        label="test"
      />,
    );

    expect(titles(container)).toEqual([
      "2026-08-01 · Alpha: 3",
      "2026-08-01 · Beta: 1",
    ]);
  });

  it("draws a taller segment for a bigger number", () => {
    const { container } = render(
      <BarStack
        rows={[{ day: "2026-08-01", a: 10, b: 1 }]}
        series={TWO}
        label="test"
      />,
    );

    const [big, small] = [...container.querySelectorAll("rect.chart-mark")].map((rect) =>
      Number(rect.getAttribute("height")),
    );
    expect(big).toBeGreaterThan(small);
  });

  it("omits a zero segment rather than drawing a hairline for it", () => {
    // A 0 with a `Math.max(…, 1)` floor would still paint a 1px line, which reads as a
    // small amount of something on a day that had none of it.
    const { container } = render(
      <BarStack rows={[{ day: "2026-08-01", a: 5, b: 0 }]} series={TWO} label="t" />,
    );

    expect(container.querySelectorAll("rect.chart-mark")).toHaveLength(1);
  });

  it("scales every day against the same axis", () => {
    // The bug this catches is a per-column scale, where every bar is full height and the
    // chart says nothing at all. A quiet day beside a busy one must be visibly shorter.
    const { container } = render(
      <BarStack
        rows={[
          { day: "2026-08-01", a: 100, b: 0 },
          { day: "2026-08-02", a: 1, b: 0 },
        ]}
        series={TWO}
        label="test"
      />,
    );

    const [busy, quiet] = [...container.querySelectorAll("rect.chart-mark")].map((rect) =>
      Number(rect.getAttribute("height")),
    );
    expect(busy).toBeGreaterThan(quiet * 10);
  });
});

describe("TrendLine", () => {
  const ONE: Series[] = [{ key: "v", label: "Latency", color: "var(--chart-1)" }];

  it("breaks the line at a null instead of joining across it", () => {
    // Joining would draw a slope through a day nothing was measured on — a shape that
    // never happened, invented from a gap. Two runs of two points make two polylines.
    const { container } = render(
      <TrendLine
        rows={[
          { day: "2026-08-01", v: 10 },
          { day: "2026-08-02", v: 20 },
          { day: "2026-08-03", v: null },
          { day: "2026-08-04", v: 30 },
          { day: "2026-08-05", v: 40 },
        ]}
        series={ONE}
        label="test"
      />,
    );

    expect(container.querySelectorAll("polyline.chart-line")).toHaveLength(2);
  });

  it("draws a lone measurement as a dot, so it is not invisible", () => {
    const { container } = render(
      <TrendLine
        rows={[
          { day: "2026-08-01", v: null },
          { day: "2026-08-02", v: 12 },
          { day: "2026-08-03", v: null },
        ]}
        series={ONE}
        label="test"
      />,
    );

    expect(container.querySelectorAll("polyline.chart-line")).toHaveLength(0);
    expect(container.querySelectorAll("circle.chart-dot")).toHaveLength(1);
  });

  it("gives a null day no hit target and no title", () => {
    const { container } = render(
      <TrendLine
        rows={[
          { day: "2026-08-01", v: 5 },
          { day: "2026-08-02", v: null },
        ]}
        series={ONE}
        label="test"
      />,
    );

    expect(container.querySelectorAll("circle.chart-hit")).toHaveLength(1);
    expect(titles(container)).toEqual(["2026-08-01 · Latency: 5"]);
  });
});

describe("HBar", () => {
  it("draws the longest bar full width and the rest in proportion", () => {
    const { container } = render(
      <HBar
        rows={[
          { name: "alice", value: 100 },
          { name: "bob", value: 25 },
        ]}
      />,
    );

    const widths = [...container.querySelectorAll<HTMLElement>(".hbar-fill")].map(
      (fill) => fill.style.width,
    );
    expect(widths).toEqual(["100%", "25%"]);
  });

  it("sizes the inset against its own bar, not against the chart", () => {
    // The inset is *of which*, so 5 refusals inside 20 calls is a quarter of that bar —
    // measuring it against the leader's 100 would draw every caller's refusals as a
    // sliver and hide the one caller who is mostly being refused.
    const { container } = render(
      <HBar
        rows={[
          { name: "alice", value: 100, inset: 0 },
          { name: "bob", value: 20, inset: 5 },
        ]}
      />,
    );

    const inset = container.querySelector<HTMLElement>(".hbar-inset");
    expect(inset?.style.width).toBe("25%");
  });
});

describe("Meter", () => {
  it("draws no track at all when the limit is not enforced", () => {
    // The trap this exists for: a bar at 0% is the most confident possible rendering of
    // a number nobody is counting.
    const { container } = render(
      <Meter value={400} of={null} caption="not enforced" />,
    );

    expect(container.querySelector(".meter-track")).toBeNull();
    expect(screen.getByText("400")).toBeInTheDocument();
  });

  it("warns before it is full, and never overflows its track", () => {
    const { container } = render(<Meter value={950} of={1000} caption="x" />);
    expect(container.querySelector(".meter-fill")).toHaveClass("bad");

    const { container: over } = render(<Meter value={5000} of={1000} caption="x" />);
    expect(over.querySelector<HTMLElement>(".meter-fill")?.style.width).toBe("100%");
  });
});

describe("Figure", () => {
  it("shows a legend for two series and none for one", () => {
    const { container, rerender } = render(
      <Figure title="Two" series={TWO}>
        <svg />
      </Figure>,
    );
    expect(container.querySelector(".legend")).not.toBeNull();
    expect(screen.getByText("Alpha")).toBeInTheDocument();

    rerender(
      <Figure title="One" series={[TWO[0]]}>
        <svg />
      </Figure>,
    );
    // One colour needs no key: the title already says what is plotted, and a box with a
    // single swatch restates it.
    expect(container.querySelector(".legend")).toBeNull();
  });

  it("keeps the numbers reachable behind a disclosure", () => {
    render(
      <Figure title="T" table={<table><tbody><tr><td>42</td></tr></tbody></table>}>
        <svg />
      </Figure>,
    );

    expect(screen.getByText("Show the numbers")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
  });
});
