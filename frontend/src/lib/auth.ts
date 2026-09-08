/** Authorization Code + PKCE, in the browser. The token lives in this module's memory.
 *
 * `backend/scripts/dev_token.py` is the reference implementation of this exchange and
 * has been working against the same Okta org for two steps — same issuer, same client
 * id, same redirect URI, same PKCE. What is new here is the two things a script never
 * has to do: **hold the token without writing it anywhere durable**, and **replace it
 * before it expires without interrupting whoever is using the page.**
 *
 * ## Where the token is, and what that costs
 *
 * A module-scope variable. Not `localStorage`, not `sessionStorage`, not a cookie:
 *
 *   - it does not survive a reload, so a machine left logged in overnight holds nothing
 *   - it is not readable from another tab
 *   - **it is readable by any script that runs in this page**
 *
 * That last one is decision 5's stated cost and it is not mitigated by where the
 * variable lives. An XSS here gets an access token. The mitigation is the CSP in
 * `index.html` and a refusal to add third-party scripts, and the upgrade — an HttpOnly
 * session cookie, which means the server gains `/login`, a session store and CSRF on
 * every mutating route — is deferred with a trigger: the first enterprise security
 * questionnaire, which asks this question directly.
 *
 * ## Not surviving a reload is a design problem, and this is the answer
 *
 * If losing the token meant a login screen, every refresh would be a sign-in prompt and
 * somebody would put the token in `localStorage` within a week. So the app does not
 * start by asking whether it has a token — it starts by **asking the provider for one
 * silently** (`prompt=none`, in a hidden iframe). The person still has a session at the
 * provider, so it comes back in a few hundred milliseconds and they never see a screen.
 * Only when *that* fails is there anything to sign in to.
 *
 * ## Two ways to renew, and the second exists because of third-party cookies
 *
 * The iframe carries the provider's session cookie as a **third-party** cookie, and
 * browsers are in the middle of taking that away. When the iframe comes back
 * `login_required` on a person who plainly is logged in, that is what happened.
 *
 * So the fallback is a **top-level redirect**, where the same cookie is first-party and
 * works. It costs the page: React unmounts, the browser leaves, comes back, and remounts
 * — which is nearly free here only because decision 6 means there is no client state to
 * lose. Anything typed and not submitted is lost, which is the one real cost and the
 * reason it is second rather than first.
 *
 * **This is no longer hypothetical.** It was observed in Brave with default shields, in
 * the worst arrangement: a person who had just completed an interactive login, whose
 * provider session was minutes old, got `login_required` from the iframe on the very
 * next page load. Whether it also happens in a browser that still permits third-party
 * cookies is *not established* — but the mechanism above is exactly what it looked like,
 * and the paragraph was written before it was seen.
 *
 * What was wrong when it was seen, and is fixed: **a refusal took twenty seconds to
 * notice.** Okta answers a refused `prompt=none` with a 400 HTML page rather than a
 * redirect carrying `error=login_required`, so nothing posted back and only the timeout
 * ended the wait. See `SILENT_GRACE_MS`. A reload now reaches the sign-in screen in
 * about a second, and signing in returns to the page it was opened over.
 *
 * ## Why `boot()` still does not use the redirect fallback, though `renew()` does
 *
 * The obvious next step is to make a failed boot redirect rather than show a screen —
 * the provider has the session, so a reload would round-trip invisibly and never
 * interrupt anybody. It is deliberately **not** done, for a reason found by tracing it:
 *
 * `renew()`'s loop guard refuses a second redirect within 30 seconds and signs out
 * saying *"signing in did not produce a usable session"*. That is right for a genuine
 * loop and wrong for a boot, because **reloading a page twice in half a minute is
 * ordinary** — and each reload legitimately needs its own redirect. Routing boot through
 * it would tell somebody their session was broken when it was not.
 *
 * So auto-redirect on boot needs the guard redesigned to count *consecutive failures to
 * obtain a token* rather than redirects-per-interval. That is a small change and it is a
 * product decision as well as a mechanical one — it removes the app's own sign-in screen
 * for everybody — and it belongs with the HttpOnly session upgrade, which removes the
 * question entirely. `DEFERRED.md` has the row.
 *
 * Refresh tokens are the other answer and are deliberately not taken: a refresh token in
 * browser memory is a longer-lived credential with the same XSS exposure, and it wants
 * rotation and reuse detection to be worth having.
 */

/** Where the provider is, learned at runtime rather than baked at build.
 *
 *  Two sources, in order: `/config.json`, served beside the bundle — both front doors
 *  serve one, and an enterprise deployment can drop a static file next to `dist/`
 *  instead of rebuilding — then the `VITE_OIDC_*` variables, which remain the
 *  dev-server story. No hardcoded default: the old fallback was a real Okta org's
 *  ids, which meant a misconfigured deployment silently sent people to *our* provider
 *  instead of saying what was missing.
 *
 *  The issuer is the provider's **issuer URL** — the same string `--add-idp` registers
 *  on the backend — and the endpoints are resolved from its OIDC discovery document
 *  (see `endpoints()`), not by concatenating paths onto it. The module used to build
 *  `${issuer}/v1/authorize`, which is Okta's URL shape and nobody else's: no "endpoint
 *  base" can express Entra (`…/oauth2/v2.0/authorize`), Keycloak
 *  (`…/protocol/openid-connect/auth`) or Google, whose token endpoint is on a
 *  different origin from its issuer. Discovery is what every provider actually
 *  standardizes. An origin-relative issuer (`/idp`, the local mode's) still works —
 *  its discovery document is fetched from the page's own origin, which is exactly
 *  what keeps the local mode inside the CSP's `'self'`. */
interface ProviderConfig {
  issuer: string;
  clientId: string;
  scopes: string;
}

/** The two endpoints this module uses, out of the discovery document. */
interface ProviderEndpoints {
  authorize: string;
  token: string;
}

let provider: ProviderConfig | null = null;

const NO_PROVIDER =
  "no identity provider is configured for this deployment. Serve a /config.json " +
  "beside the app (carnet --local does), or set VITE_OIDC_ISSUER and " +
  "VITE_OIDC_CLIENT_ID.";

/** Set when a `/config.json` *was* served and could not be used — which is a different
 *  problem from there not being one, and has a different remedy.
 *
 *  **This is the original defect's own shape, and it can come back through a door this
 *  step cannot close.** A front door that sends `/config.json` through the SPA fallback
 *  answers it with `index.html` and a **200**, so `response.ok` is true and only the
 *  JSON parse fails — which is exactly how a deployment nobody could sign into reported
 *  nothing anywhere. The shipped front doors both 404 correctly now, but
 *  `deploy/README.md` invites a customer to replace the front door, and obligation four
 *  is the one they can get wrong. So the case gets a sentence naming what came back
 *  instead of falling through to "nothing is configured", which would send whoever
 *  reads it to check a file that is already right. */
let configProblem = "";

/** Resolve the provider before anything needs it. Called once from `main.tsx`, before
 *  React mounts; safe to call again (the result is kept). Never throws — a page that
 *  cannot find its provider still mounts, and says so on the sign-in screen. */
export async function loadProviderConfig(): Promise<void> {
  if (provider) return;
  try {
    const response = await fetch("/config.json");
    if (response.ok) {
      const body = await response.text();
      let found: { issuer?: string; client_id?: string; scopes?: string } | null = null;
      try {
        // Parsed rather than content-type-gated on purpose: a deployment serving
        // valid JSON as text/plain is still telling the truth, and refusing it would
        // be this module inventing a requirement. The type is only *reported*, below,
        // because "text/html" is the whole diagnosis when a parse fails.
        found = JSON.parse(body);
      } catch {
        const type = response.headers.get("content-type") ?? "an unstated type";
        configProblem =
          `/config.json was served as ${type} and is not JSON, so this app cannot ` +
          `find its identity provider. If a proxy or ingress is serving this app, ` +
          `it is answering /config.json with the single-page fallback instead of ` +
          `the file — /config.json must be served as itself, and be a real 404 when ` +
          `there is none.`;
      }
      if (found && found.issuer && found.client_id) {
        provider = {
          issuer: found.issuer,
          clientId: found.client_id,
          scopes: found.scopes ?? "openid profile email",
        };
        configProblem = "";
        return;
      }
      if (found) {
        configProblem =
          "/config.json was served but names no issuer and no client_id, so this " +
          "app cannot find its identity provider.";
      }
    }
  } catch {
    // No config.json is the ordinary case on the dev server; the env vars are next.
  }
  if (import.meta.env.VITE_OIDC_ISSUER && import.meta.env.VITE_OIDC_CLIENT_ID) {
    provider = {
      issuer: import.meta.env.VITE_OIDC_ISSUER,
      clientId: import.meta.env.VITE_OIDC_CLIENT_ID,
      scopes: import.meta.env.VITE_OIDC_SCOPES ?? "openid profile email",
    };
    configProblem = "";
  }
}

function required(): ProviderConfig {
  if (!provider) throw new AuthError(configProblem || NO_PROVIDER);
  return provider;
}

let endpointsPromise: Promise<ProviderEndpoints> | null = null;

/** Resolve the provider's endpoints from its OIDC discovery document.
 *
 *  Lazily, on the first operation that needs one — never from `loadProviderConfig`,
 *  which runs before React mounts: a slow or unreachable issuer must not block the
 *  page from appearing. Cached for the life of the page on success; a *failure* is
 *  deliberately not cached, so a provider that was briefly unreachable is retried on
 *  the next sign-in attempt rather than being broken until a reload.
 *
 *  The fetch goes to the issuer's own origin, which the served CSP's `connect-src`
 *  already names — the same directive the token exchange needs. */
async function endpoints(): Promise<ProviderEndpoints> {
  const { issuer } = required();
  endpointsPromise ??= (async () => {
    const url = `${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`;
    let response: Response;
    try {
      response = await fetch(url);
    } catch (cause) {
      throw new AuthError(
        `could not fetch the identity provider's discovery document from ${url}. ` +
          `Either the provider is not reachable from this browser, or this page's ` +
          `Content-Security-Policy does not allow its origin.`,
        { cause },
      );
    }
    if (!response.ok) {
      throw new AuthError(
        `the identity provider answered ${response.status} for its discovery ` +
          `document at ${url} — is the configured issuer exactly the provider's ` +
          `issuer URL?`,
      );
    }
    let doc: { authorization_endpoint?: string; token_endpoint?: string };
    try {
      doc = await response.json();
    } catch (cause) {
      // The same trap as `/config.json`, one layer out: a 200 that is not JSON. A
      // provider fronted by a captive portal or an error page answers exactly this,
      // and an unhandled SyntaxError would reach the sign-in screen as
      // "Unexpected token <" — a sentence about nothing.
      throw new AuthError(
        `the identity provider answered ${url} with something that is not JSON, so ` +
          `its endpoints could not be read. Is the configured issuer exactly the ` +
          `provider's issuer URL?`,
        { cause },
      );
    }
    if (!doc.authorization_endpoint || !doc.token_endpoint) {
      throw new AuthError(
        `the discovery document at ${url} names no authorization_endpoint or no ` +
          `token_endpoint`,
      );
    }
    return { authorize: doc.authorization_endpoint, token: doc.token_endpoint };
  })();
  try {
    return await endpointsPromise;
  } catch (error) {
    endpointsPromise = null;
    throw error;
  }
}

/** Registered at the provider, so it is derived from the origin rather than configured
 *  separately — two places to write a URL is one place for them to disagree. The dev
 *  server pins port 8080 for this reason; see vite.config.ts. */
export const REDIRECT_URI = `${window.location.origin}/login/callback`;

export const CALLBACK_PATH = "/login/callback";

/** Renew this long before the token actually expires. One minute is enough for a
 *  request already in flight and short enough that a person on a five-minute visit
 *  never renews at all. */
const RENEW_MARGIN_MS = 60_000;

/** The backstop, for an iframe that never loads at all — a hung network, a provider that
 *  accepts the connection and never answers. It is **not** how a refusal is detected; see
 *  `SILENT_GRACE_MS`. */
const SILENT_TIMEOUT_MS = 20_000;

/** How long to keep waiting after the iframe has finished loading something.
 *
 *  **This number is the fix for a 20-second stall, and the stall was the visible half of
 *  a real failure.** A provider refusing `prompt=none` does not have to answer with a
 *  redirect carrying `error=login_required`. Okta answers with a **400 and an HTML error
 *  page**, which loads in the iframe and posts nothing — so the only thing that ever
 *  ended this wait was the timeout above, and every failed silent sign-in cost twenty
 *  seconds of "Signing you in…" before the sign-in screen appeared.
 *
 *  An iframe fires `load` for a cross-origin document even though its content cannot be
 *  read, and that is enough: something arrived and it was not our callback. The success
 *  path posts its message from `main.tsx` *before* React mounts and therefore before
 *  `load` fires, so by the time this grace period starts a good outcome has already
 *  resolved. The grace exists only so the ordering does not have to be relied on. */
const SILENT_GRACE_MS = 1_000;

// sessionStorage, and only ever these. A PKCE verifier is single-use, worthless once
// exchanged, and useless to anybody who cannot also make the browser follow the
// redirect. The *token* is what does not go here.
const VERIFIER_KEY = "carnet.pkce.verifier";
const STATE_KEY = "carnet.pkce.state";
const RETURN_KEY = "carnet.pkce.return";
const LAST_REDIRECT_RENEW_KEY = "carnet.renew.last";

export interface Claims {
  /** For the Okta org `sub` is the email and `uid` is the opaque id — `email_claim=sub`,
   *  `subject_claim=uid`, per migration 010, which exists because of a real token. The
   *  local provider is spec-shaped instead: `sub` is the opaque id and `email` is the
   *  address. Display code prefers `email ?? sub`, which is right under both. */
  sub?: string;
  uid?: string;
  email?: string;
  name?: string;
  exp?: number;
}

export type Session =
  | { state: "unknown" }
  | { state: "in"; claims: Claims }
  | { state: "out"; reason: string };

let token: string | null = null;
let expiresAt = 0;
let claims: Claims = {};
let session: Session = { state: "unknown" };
let renewTimer: ReturnType<typeof setTimeout> | undefined;
let inFlight: Promise<boolean> | null = null;

// --- the bit React subscribes to ---------------------------------------------------
//
// Not a state library. This is one value with one writer, and `useSyncExternalStore`
// is the built-in way to read it without a second copy going stale — which is the
// whole of decision 6 applied to the one piece of state that genuinely is the client's.

const listeners = new Set<() => void>();

export function subscribe(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function current(): Session {
  return session;
}

function publish(next: Session): void {
  session = next;
  listeners.forEach((fn) => fn());
}

// --- PKCE ---------------------------------------------------------------------------

function base64url(bytes: Uint8Array): string {
  let s = "";
  bytes.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomString(bytes = 48): string {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function challengeFor(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return base64url(new Uint8Array(digest));
}

/** Read the claims out of a token this client just fetched over TLS from the issuer.
 *
 *  **Read, never verified** — there is nothing here to verify against, and a client that
 *  pretended to check a signature would be teaching the wrong lesson. The server checks
 *  it. This is for putting a name in the corner of the page, and for nothing else.
 *  Same note as `dev_token.py`, for the same reason. */
function readClaims(jwt: string): Claims {
  try {
    const payload = jwt.split(".")[1];
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(json) as Claims;
  } catch {
    return {};
  }
}

async function authorizeUrl(extra: Record<string, string>): Promise<string> {
  const { clientId, scopes } = required();
  const { authorize } = await endpoints();
  const verifier = randomString();
  const state = randomString(16);
  sessionStorage.setItem(VERIFIER_KEY, verifier);
  sessionStorage.setItem(STATE_KEY, state);

  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    scope: scopes,
    redirect_uri: REDIRECT_URI,
    state,
    code_challenge: await challengeFor(verifier),
    code_challenge_method: "S256",
    ...extra,
  });
  const joiner = authorize.includes("?") ? "&" : "?";
  return `${authorize}${joiner}${params}`;
}

export class AuthError extends Error {}

async function exchange(code: string): Promise<void> {
  const verifier = sessionStorage.getItem(VERIFIER_KEY);
  if (!verifier) {
    throw new AuthError(
      "the sign-in could not be completed because this tab did not start it",
    );
  }

  const { clientId } = required();
  const { token: tokenEndpoint } = await endpoints();
  let response: Response;
  try {
    response = await fetch(tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier,
      }),
    });
  } catch (cause) {
    // A browser cannot tell a script the difference between "no network", "the page's
    // CSP blocked the request" and "the provider refused the cross-origin request" —
    // so the message names all three, in the order they are usually true. (For Okta,
    // the third means the origin is missing from the app's Trusted Origins.)
    throw new AuthError(
      `could not reach the identity provider's token endpoint from ` +
        `${window.location.origin}. Either the provider is not running, this page's ` +
        `Content-Security-Policy does not allow its origin, or the provider has not ` +
        `been told to accept requests from this origin (CORS / Trusted Origins).`,
      { cause },
    );
  } finally {
    sessionStorage.removeItem(VERIFIER_KEY);
    sessionStorage.removeItem(STATE_KEY);
  }

  if (!response.ok) {
    const body = await response.text();
    throw new AuthError(`the identity provider refused the exchange: ${body}`);
  }

  const tokens = (await response.json()) as {
    access_token: string;
    expires_in?: number;
  };
  adopt(tokens.access_token, tokens.expires_in ?? 3600);
}

function adopt(accessToken: string, expiresIn: number): void {
  token = accessToken;
  expiresAt = Date.now() + expiresIn * 1000;
  claims = readClaims(accessToken);

  clearTimeout(renewTimer);
  renewTimer = setTimeout(
    () => void renew(),
    Math.max(5_000, expiresIn * 1000 - RENEW_MARGIN_MS),
  );

  publish({ state: "in", claims });
}

// --- the three ways in --------------------------------------------------------------

/** Sign in, deliberately. A top-level redirect, and the page does not come back. */
export async function signIn(returnTo?: string): Promise<never> {
  sessionStorage.setItem(
    RETURN_KEY,
    returnTo ?? window.location.pathname + window.location.search,
  );
  window.location.assign(await authorizeUrl({}));
  return new Promise<never>(() => {});
}

/** Handle `/login/callback` at the top level: exchange the code and say where to go.
 *
 *  Deduplicated, because an authorization code is single-use and React's StrictMode
 *  mounts every component twice in development. The second exchange would fail against
 *  a spent code, at a moment when nothing is wrong — which is a bug that exists only
 *  where it is being looked for. */
export function completeSignIn(): Promise<string> {
  completing ??= exchangeFromUrl();
  return completing;
}
let completing: Promise<string> | null = null;

async function exchangeFromUrl(): Promise<string> {
  const params = new URLSearchParams(window.location.search);
  const returnTo = sessionStorage.getItem(RETURN_KEY) ?? "/";
  sessionStorage.removeItem(RETURN_KEY);

  const error = params.get("error");
  if (error) {
    throw new AuthError(
      `${error}: ${params.get("error_description") ?? "no further detail"}`,
    );
  }

  const expected = sessionStorage.getItem(STATE_KEY);
  if (!params.get("state") || params.get("state") !== expected) {
    // Not ceremony. A mismatch means this response is not the one this tab asked for,
    // and continuing would be exchanging a code somebody else obtained.
    throw new AuthError("the sign-in response did not match this tab's request");
  }

  const code = params.get("code");
  if (!code) throw new AuthError("no authorization code came back");

  await exchange(code);
  return returnTo;
}

/** Ask the provider for a token without showing anybody anything.
 *
 *  Used on boot — which is what makes an in-memory token survivable — and to replace a
 *  token before it expires. Resolves `false` when the person has to be shown something,
 *  which is not an error: it is the ordinary answer for somebody who is not signed in. */
export async function silentSignIn(): Promise<boolean> {
  const url = await authorizeUrl({ prompt: "none" });

  const frame = document.createElement("iframe");
  frame.style.display = "none";
  frame.setAttribute("aria-hidden", "true");
  frame.title = "silent sign-in";

  const outcome = new Promise<URLSearchParams | null>((resolve) => {
    const timer = setTimeout(() => finish(null), SILENT_TIMEOUT_MS);
    let grace: ReturnType<typeof setTimeout> | undefined;
    let done = false;

    function onMessage(event: MessageEvent) {
      // Same origin only. The callback page inside the frame is ours; anything else
      // posting here is somebody else's page and is ignored rather than parsed.
      if (event.origin !== window.location.origin) return;
      const data = event.data as { type?: string; search?: string } | null;
      if (!data || data.type !== "carnet-auth-callback") return;
      finish(new URLSearchParams(data.search ?? ""));
    }

    /** The iframe finished loading *something*.
     *
     *  If it were our callback it would already have posted, so this is a refusal
     *  wearing whatever shape the provider chose — for Okta, a 400 error page. Reading
     *  it is impossible and unnecessary: the outcome is the same either way, and the
     *  point is to stop waiting twenty seconds to reach it. */
    function onLoad() {
      if (done || grace) return;
      grace = setTimeout(() => finish(null), SILENT_GRACE_MS);
    }

    function finish(result: URLSearchParams | null) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      clearTimeout(grace);
      window.removeEventListener("message", onMessage);
      frame.removeEventListener("load", onLoad);
      frame.remove();
      resolve(result);
    }

    window.addEventListener("message", onMessage);
    frame.addEventListener("load", onLoad);
  });

  frame.src = url;
  document.body.appendChild(frame);

  const params = await outcome;
  if (!params) return false;

  if (params.get("state") !== sessionStorage.getItem(STATE_KEY)) return false;
  const code = params.get("code");
  if (!code) return false; // `login_required`, `interaction_required`, or a timeout.

  await exchange(code);
  return true;
}

/** Replace the token, silently if the browser will allow it and by leaving the page if
 *  it will not. Concurrent callers share one attempt — a page with four requests in
 *  flight when a token expires must not start four sign-ins. */
export function renew(): Promise<boolean> {
  if (inFlight) return inFlight;

  const attempt = (async () => {
    try {
      if (await silentSignIn()) return true;
    } catch {
      // Fall through: an exchange that failed inside the iframe is still a renewal
      // that did not happen, and the redirect below is the thing that recovers it.
    }

    // The iframe was refused. Usually third-party cookies; occasionally a session that
    // genuinely ended. A top-level redirect tells the two apart, because there the
    // provider's cookie is first-party.
    //
    // **With a loop guard**, because "redirect to fix authentication" is the single
    // easiest way to build an infinite one — and a loop that redirects through an
    // identity provider is one a person cannot even read the page to escape.
    const last = Number(sessionStorage.getItem(LAST_REDIRECT_RENEW_KEY) ?? 0);
    if (Date.now() - last < 30_000) {
      signOut("signing in did not produce a usable session — please sign in again");
      return false;
    }
    sessionStorage.setItem(LAST_REDIRECT_RENEW_KEY, String(Date.now()));
    await signIn();
    return false;
  })();

  inFlight = attempt;
  void attempt.finally(() => {
    if (inFlight === attempt) inFlight = null;
  });
  return attempt;
}

/** Start-up: adopt a session if the provider will give one, without a screen.
 *
 *  Runs once per page load however many times it is called — same StrictMode reason as
 *  `completeSignIn`, and here a second call would mean a second hidden iframe. */
export function boot(): Promise<void> {
  booting ??= bootOnce();
  return booting;
}
let booting: Promise<void> | null = null;

async function bootOnce(): Promise<void> {
  try {
    if (await silentSignIn()) return;
    publish({ state: "out", reason: "" });
  } catch (error) {
    publish({
      state: "out",
      reason: error instanceof Error ? error.message : String(error),
    });
  }
}

export function signOut(reason = ""): void {
  token = null;
  expiresAt = 0;
  claims = {};
  clearTimeout(renewTimer);
  publish({ state: "out", reason });
}

// --- what api.ts asks -----------------------------------------------------------------

/** The token to send, renewing first if it is about to expire.
 *
 *  Proactive, so an expiring token is normally replaced before a request rather than
 *  after a 401. The 401 path still exists — a token can be rejected for reasons this
 *  side cannot see, and a clock can be wrong. */
export async function bearer(): Promise<string | null> {
  if (token && Date.now() > expiresAt - RENEW_MARGIN_MS) await renew();
  return token;
}

export function signedIn(): boolean {
  return token !== null;
}

/** The callback page, when it is running inside the silent-renewal iframe.
 *
 *  Called from `main.tsx` **before React mounts**, because rendering an application
 *  inside a hidden iframe would boot a second copy of everything — including another
 *  silent sign-in, recursively.
 *
 *  Returns true when it handled the load and the caller must render nothing. */
export function postCallbackToOpener(): boolean {
  const inFrame = window.parent !== window;
  if (!inFrame || window.location.pathname !== CALLBACK_PATH) return false;

  window.parent.postMessage(
    { type: "carnet-auth-callback", search: window.location.search },
    window.location.origin,
  );
  return true;
}
