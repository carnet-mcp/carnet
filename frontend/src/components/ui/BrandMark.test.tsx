/** The vendor marks, and the three things a logo tile on an administration page must not
 *  get wrong.
 *
 *   - **it never renders nothing.** A connector is named by whatever an administrator typed,
 *     and most of those will match no brand at all. Every one of them still gets a tile —
 *     a monogram is plain, and plain is not the same as absent.
 *   - **it fetches nothing.** A logo pulled from a vendor's CDN would tell an outside party
 *     which vendors a customer has connected, on every render, and would need the CSP
 *     widened to let it. There is no `<img>` here and there must never be one.
 *   - **a tile is decoration beside a name that is already on the screen**, so it is
 *     `aria-hidden` — `Icon`'s rule, for `Icon`'s reason.
 */

import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { BrandMark, brandOf } from "./BrandMark";

describe("brandOf", () => {
  it("finds a vendor in a recipe id, a connector id or a hostname", () => {
    expect(brandOf("github-mcp-hosted")?.label).toBe("GitHub");
    expect(brandOf("jira")?.label).toBe("Jira");
    expect(brandOf(null, "mcp.atlassian.com")?.label).toBe("Jira");
    expect(brandOf("anthropic-messages")?.label).toBe("Anthropic");
  });

  it("matches on a substring, which is a cosmetic guess and says so", () => {
    // `internal-github-proxy` getting GitHub's mark is probably right; a connector called
    // `notion-export-cleanup` getting Notion's is arguable. It is cosmetic either way and
    // the fallback is never wrong, only plain — see the plan's known limits.
    expect(brandOf("internal-github-proxy")?.label).toBe("GitHub");
  });

  it("answers null for the connector nobody has heard of", () => {
    expect(brandOf("acme")).toBeNull();
    expect(brandOf("")).toBeNull();
    expect(brandOf(undefined, null)).toBeNull();
  });
});

describe("the tile", () => {
  it("draws a mark for a vendor that has one", () => {
    const { container } = render(<BrandMark hints={["github"]} />);
    expect(container.querySelectorAll("svg path").length).toBeGreaterThan(0);
  });

  it("falls back to an initial rather than to nothing", () => {
    // The case that is most of them: an id an administrator invented.
    const { container } = render(<BrandMark hints={["acme"]} />);
    expect(container.querySelector("svg")).toBeNull();
    expect(container.querySelector(".brandmark-letter")?.textContent).toBe("A");
  });

  it("takes a vendor's own letter over the id's first character", () => {
    // OpenAI has no drawn mark on purpose — its knot is not something to approximate —
    // so the row carries the letter instead of leaving it to `openai-chat`'s "O", which
    // happens to agree and would not have to.
    const { container } = render(<BrandMark hints={["openai-chat"]} />);
    expect(container.querySelector(".brandmark-letter")?.textContent).toBe("O");
  });

  it("survives an id with nothing alphanumeric in it", () => {
    const { container } = render(<BrandMark hints={["---"]} />);
    expect(container.querySelector(".brandmark-letter")?.textContent).toBe("?");
  });

  it("gives one id one colour, every time", () => {
    // The hue is decorative and means nothing — it exists so eight unrecognised
    // connectors are eight tiles rather than a column of identical grey squares. What it
    // must do is be stable: a card that changes colour on reload reads as a different card.
    const a = render(<BrandMark hints={["acme"]} />).container.innerHTML;
    const b = render(<BrandMark hints={["acme"]} />).container.innerHTML;
    expect(a).toBe(b);
  });

  it("loads nothing over the network and announces nothing", () => {
    const { container } = render(<BrandMark hints={["github"]} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector(".brandmark")).toHaveAttribute("aria-hidden", "true");
  });
});
