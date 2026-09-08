/** The test runner, and the reason it exists is a bug rather than a policy.
 *
 * `frontend/` shipped 5,000 lines with no tests. The one bug 10a found — the dev proxy
 * claiming `/agents` and `/runs`, which are also the app's own routes, so a **reload**
 * returned the API's 401 JSON where the app should be — is exactly the class that one
 * request-level assertion catches. The reason none existed is that every click-through
 * path in a SPA avoids the server entirely, which is what hid the collision.
 *
 * 10b then shipped a second bug of the same family: the singular branch of a sentence
 * read "One tool that alter a system", visible on the most important line of the screen
 * and invisible to every check in this repository. Two for two is enough.
 *
 * Separate from `vite.config.ts` on purpose. That file configures a **dev server** whose
 * proxy, port and CSP relaxation are all load-bearing and all irrelevant here; importing
 * it would mean a test run depended on an OAuth redirect URI.
 */

import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
