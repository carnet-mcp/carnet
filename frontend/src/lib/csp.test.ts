/** The shipped `<meta>` policy, and the one property it must keep having.
 *
 * **This file exists because CI cannot run the checks that would otherwise catch
 * this.** Step 031 moved `connect-src`, `frame-src` and `default-src` out of
 * `index.html` and into a header the front door composes from the deployment's
 * declared identity provider. The reason is not style: two policies delivered to one
 * document are enforced as their **intersection**, so anything the meta tag restricts,
 * the header can never widen. A `connect-src` in this file — even one that looks
 * generous — silently re-imposes itself on every deployment and blocks whatever
 * provider the customer actually configured. That is the exact defect 031 was built to
 * fix, and re-adding one line here brings all of it back.
 *
 * `default-src` counts, and is the subtle half: a directive that is *absent* from a
 * policy falls back to that policy's `default-src`, so leaving `default-src 'self'`
 * here would go on governing connections at `'self'` no matter what the header said.
 *
 * The assertions that would otherwise cover this live in `e2e_deploy.py` and
 * `e2e_browser_deploy.py`, both of which need Docker and **neither of which CI runs**
 * (`.github/workflows/tests.yml` has no deploy or browser job). vitest does run, and
 * this file is one `readFileSync` — so the invariant gets a guard on the one runner
 * that is always watching.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

// From the project root, not from `import.meta.url`: these tests run under jsdom,
// where `import.meta.url` is an `http://` URL and `fileURLToPath` refuses it. vitest's
// cwd is the directory holding `vitest.config.ts`, which is where `index.html` lives.
const INDEX = readFileSync(resolve(process.cwd(), "index.html"), "utf8");

/** The `content="..."` of the CSP meta tag, or "" if the tag is gone. */
function metaPolicy(): string {
  const tag = /http-equiv="Content-Security-Policy"[\s\S]*?content="([^"]*)"/.exec(
    INDEX,
  );
  return tag ? tag[1] : "";
}

describe("the policy that ships in the bundle", () => {
  it("still carries the directive that is the whole mitigation", () => {
    // The access token lives in this page's memory, so a script that runs here can
    // read it. `script-src 'self'` is what keeps a script from running, and unlike
    // the provider-dependent directives it travels with the bundle to every
    // deployment — including one whose ingress forgets to send the header at all.
    expect(metaPolicy()).toContain("script-src 'self'");
  });

  it("does not allow inline script", () => {
    // `'unsafe-inline'` belongs to `style-src` and to nothing else. The dev server
    // adds it to `script-src` at serve time (vite.config.ts) because React's refresh
    // preamble is inline; this file is what ships.
    const beforeStyle = metaPolicy().split("style-src")[0];
    expect(beforeStyle).not.toContain("unsafe-inline");
  });

  it.each(["default-src", "connect-src", "frame-src"])(
    "does not carry %s, which only the front door can know",
    (directive) => {
      // If this fails, read the file docstring before "fixing" it by relaxing the
      // value: any value here narrows every deployment's policy by intersection, and
      // the deployment's own provider is not knowable from this file.
      expect(metaPolicy()).not.toContain(directive);
    },
  );

  it("names no identity provider at all", () => {
    // The literal regression: `connect-src 'self' https://*.okta.com` shipped an
    // artifact that only Okta customers could sign into, and a proxy cannot widen it.
    expect(metaPolicy()).not.toContain("okta");
    expect(metaPolicy()).not.toMatch(/https?:\/\//);
  });
});
