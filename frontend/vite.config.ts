import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

/** Let the dev server run the one inline script the shipped page forbids.
 *
 * `index.html` carries a real CSP with `script-src 'self'`, which is the load-bearing
 * half of decision 5's mitigation. Vite's React plugin injects an inline module
 * preamble for hot reload, and that preamble is inline script — so under the shipped
 * policy the dev server serves a blank page and a console error about a directive
 * nobody typed.
 *
 * The alternative — dropping the meta tag and setting the header in production instead
 * — makes the mitigation a deployment step somebody forgets. So the strict policy is in
 * the file that ships, and the *development* copy is the one that is weakened, visibly
 * and in one directive.
 *
 * This plugin used to widen `connect-src`/`frame-src` for a non-Okta `VITE_OIDC_ISSUER`
 * too. Those directives left the meta tag in plan 031 (the front door serves them,
 * derived from the deployment's declared provider), so the dev server — which serves
 * no CSP header — now runs with unrestricted connections. A deliberate loss of parity
 * in the one place parity was already false, and what makes `VITE_OIDC_*` work against
 * any provider in development.
 */
function relaxCspForDev(): Plugin {
  return {
    name: "relax-csp-for-dev",
    apply: "serve",
    transformIndexHtml: (html) =>
      html.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'"),
  };
}

// The API. One origin in the browser, so there is no CORS and no preflight on every
// request — the dev server proxies the six routes rather than the app calling across
// origins. In production the same static bundle is served from wherever the API is.
//
// **`127.0.0.1`, not `localhost`.** Node stopped reordering DNS results in 17, so on
// Windows `localhost` resolves to `::1` first — and uvicorn's default bind is
// `127.0.0.1`, which does not answer there. The proxy then fails with `ECONNREFUSED`
// against a server that is plainly running and answering `curl`.
const API = process.env.VITE_API_ORIGIN ?? "http://127.0.0.1:8000";

/** **The API is reached under `/api`, and this is a bug fix rather than a convention.**
 *
 * The API's paths are `/agents` and `/runs`. So are the app's routes — `/agents` is the
 * list and `/runs/{id}` is one run. Proxying those paths verbatim means the *server*
 * claims two URLs the *client* also owns, and the two disagree about who answers:
 *
 *   clicking a link      React Router, never touches the server      the app
 *   reloading the page   a real GET to /runs/abc123                  {"detail": "..."}
 *
 * So the app worked perfectly until somebody pressed F5, and the first thing it broke
 * was the property this whole chunk exists to demonstrate — that a run outlives the tab
 * and reopening its URL rejoins it.
 *
 * Found by loading a URL rather than clicking to it. No test could have caught it:
 * every click-through path in the app avoids the server entirely, which is exactly what
 * makes the collision invisible.
 *
 * This is **not** only a dev-server problem. The plan has the same bundle served by the
 * FastAPI app in production, where those two paths collide identically. Prefixing the
 * calls is what makes the app's routes and the API's routes stop competing, wherever
 * they are served from — and it leaves the API's own URLs clean for `curl`, the CLI and
 * any future integration, which is the half that should not pay for the browser's
 * problem. A deployment serves the bundle and forwards `/api/*` onward, the same rewrite
 * as below.
 */
const proxy = {
  target: API,
  changeOrigin: true,
  rewrite: (path: string) => path.replace(/^\/api/, ""),
};

export default defineConfig(() => ({
  plugins: [react(), relaxCspForDev()],
  server: {
    // **8080, and `strictPort`, because this port is part of an OAuth registration.**
    // `http://localhost:8080/login/callback` is the redirect URI registered in the Okta
    // org — the same one `backend/scripts/dev_token.py` uses. Vite's default is 5173,
    // and on 5173 the authorize request is refused by the identity provider with an
    // error about the redirect URI that reads like a code bug.
    //
    // Falling back to 8081 when 8080 is taken would produce exactly that failure, at a
    // distance, so this fails to start instead. If 8080 is busy it is usually a stale
    // `dev_token.py` callback server or a previous `vite`.
    port: 8080,
    strictPort: true,
    // One entry, and every path the app owns is now unambiguously the app's. Anything
    // not under `/api` falls through to index.html, which is what makes a reload on
    // `/runs/abc123` land in the app instead of on a 401.
    proxy: {
      "/api": proxy,
      // Step 083. The door's OAuth discovery documents live at the origin root (RFC 9728
      // and RFC 8414 put them there, not under the API's path) and the API serves them —
      // so they are forwarded with the path intact, no rewrite. Without this the SPA
      // fallback answers them with index.html and a 200, which is `/config.json`'s old
      // defect at a new address. `deploy/Caddyfile` and `localidp/edge.py` carry the
      // same rule.
      "/.well-known/oauth-protected-resource": { target: API, changeOrigin: true },
      "/.well-known/oauth-authorization-server": { target: API, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
}));
