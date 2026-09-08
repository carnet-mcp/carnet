/** The silent sign-in, and the twenty seconds it used to cost to fail.
 *
 * `auth.ts` had no tests, and it is where the defect found in 10b's browser pass lived:
 * a provider refusing `prompt=none` answers with a **400 HTML page**, not a redirect
 * carrying `error=login_required`, so nothing posted back to the parent and only the
 * 20s timeout ended the wait. Every failed silent sign-in — which, in a browser that
 * blocks third-party cookies, is every one of them — cost twenty seconds of
 * "Signing you in…" before the sign-in screen appeared.
 *
 * These drive the real `silentSignIn` with fake timers, because what is being asserted
 * is *when* it gives up.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { loadProviderConfig, silentSignIn } from "./auth";

/** A **real** macrotask yield, captured before `vi.useFakeTimers()` ever runs.
 *
 *  Module scope is load-bearing: `useFakeTimers` is installed in `beforeEach`, so a
 *  reference taken here is the genuine one for the life of the file. See `start()` for
 *  why a real turn — rather than another fake-clock tick — is the thing that matters. */
const realSetTimeout = globalThis.setTimeout;
const realTurn = () => new Promise((resolve) => realSetTimeout(resolve, 0));

/** Hand the module a real iframe this test can drive.
 *
 *  jsdom does not navigate iframes, so `load` would never fire on its own — and `load`
 *  is the event under test. Only `createElement` is patched; the frame is appended for
 *  real, so "was it cleaned up" is answerable by asking the document. */
function captureFrame() {
  const real = document.createElement.bind(document);
  const frame = real("iframe");

  vi.spyOn(document, "createElement").mockImplementation((tag: string) =>
    tag === "iframe" ? frame : real(tag),
  );

  return {
    frame,
    inDocument: () => document.body.contains(frame),
    /** What a refused `prompt=none` looks like: a document loads and says nothing. */
    loadsSomethingThatIsNotOurCallback: () => frame.dispatchEvent(new Event("load")),
    /** What success looks like: our callback page posts, from `main.tsx`. */
    postsCallback: (search: string) =>
      window.dispatchEvent(
        new MessageEvent("message", {
          data: { type: "carnet-auth-callback", search },
          origin: window.location.origin,
        }),
      ),
    /** The state this attempt actually generated, so a test can match or mismatch it. */
    state: () => sessionStorage.getItem("carnet.pkce.state"),
  };
}

/** Start an attempt and wait until the module is actually listening.
 *
 *  **This wait is load-bearing, and getting it wrong made the whole file flaky — twice.**
 *  `silentSignIn` awaits `authorizeUrl`, which awaits a real `crypto.subtle.digest`: a
 *  genuine async operation that fake timers do not control. Advancing the clock by a fixed
 *  amount sometimes flushed it and sometimes did not, so a test would dispatch its `load`
 *  or `message` before the listeners existed and hang until vitest's timeout.
 *
 *  The first fix — this bounded poll — was still a race, just one you usually win, and it
 *  **lost on CI**: `the silent sign-in never opened its iframe`, on `main`, minutes after
 *  the same commit passed on its pull request. The reason it was still a race is the
 *  detail that matters: `advanceTimersByTimeAsync(0)` flushes **microtasks**, and
 *  `crypto.subtle.digest` resolves from a threadpool callback — a **macrotask**. Spinning
 *  on microtasks can therefore make no progress at all until that callback lands, so the
 *  loop was counting turns that could not, by construction, be the ones it was waiting
 *  for. Measured on an idle machine the wait took 1–12 ticks with no clustering; an 8×
 *  blow-up on a contended two-core runner exhausts 100.
 *
 *  So each iteration now yields a **real** event-loop turn as well, which is the only
 *  thing that lets the digest actually progress. The fake-clock tick stays because the
 *  module also schedules fake timers during startup. The bound stays as a backstop that
 *  fails with a sentence rather than hanging, and is now several orders of magnitude
 *  clear of the measured worst case rather than one bad day away from it.
 *
 *  The frame is appended *after* both listeners are attached, so its presence in the
 *  document is the signal that the module is ready to be driven. */
async function start() {
  const iframe = captureFrame();
  const attempt = silentSignIn();

  for (let tick = 0; tick < 500 && !iframe.inDocument(); tick++) {
    await realTurn();
    await vi.advanceTimersByTimeAsync(0);
  }
  if (!iframe.inDocument()) throw new Error("the silent sign-in never opened its iframe");

  return { iframe, attempt };
}

/** The provider's discovery document, with **deliberately non-Okta endpoint paths**.
 *
 *  `auth.ts` used to build `${issuer}/v1/authorize` by concatenation — Okta's URL shape
 *  and nobody else's. The endpoints are resolved from the issuer's OIDC discovery
 *  document now, and these paths are chosen so a regression to concatenation fails
 *  here by name rather than passing because the fixture happened to look like Okta. */
const ISSUER = "https://idp.test.example";
const DISCOVERY = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/oauth2/authorize`,
  token_endpoint: `${ISSUER}/oauth2/token`,
};

/** Route a stubbed `fetch`: the discovery document always answers, `/config.json` is a
 *  404 (so `loadProviderConfig` takes the env route, the same one the dev server
 *  takes), and everything else goes to `fallback` — the token endpoint, for tests that
 *  stub one. Discovery is resolved lazily and cached on first success, but no test
 *  should depend on which test resolved it, so every stub can answer it. */
function stubFetch(fallback?: (url: string) => Promise<unknown>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/.well-known/openid-configuration")) {
        return { ok: true, status: 200, json: async () => DISCOVERY };
      }
      if (url.includes("/config.json")) {
        return { ok: false, status: 404, json: async () => ({}) };
      }
      if (fallback) return fallback(url);
      throw new Error(`unexpected fetch in test: ${url}`);
    }),
  );
}

beforeAll(async () => {
  // The provider is resolved at runtime now (`/config.json`, then env). Take the env
  // route — before fake timers exist, because the config fetch is real async.
  stubFetch();
  vi.stubEnv("VITE_OIDC_ISSUER", ISSUER);
  vi.stubEnv("VITE_OIDC_CLIENT_ID", "test-client");
  await loadProviderConfig();
});

beforeEach(() => {
  vi.useFakeTimers();
  sessionStorage.clear();
});

afterEach(() => {
  // **Both lines, and the second is why this comment exists.** A test that ends while an
  // attempt is still pending leaves a `message` listener on `window`, an iframe in the
  // document and two timers on a fake clock that is about to be thrown away — and the
  // symptom was not a failure in that test, it was every *other* test in the file timing
  // out. Each test below drives its attempt to a conclusion for the same reason; this is
  // the belt.
  vi.clearAllTimers();
  vi.useRealTimers();
});

/** Drive an attempt to a conclusion, whatever it was doing. For tests whose subject is
 *  that it has NOT settled yet — leaving it pending is what poisoned the next test. */
async function settle(iframe: { loadsSomethingThatIsNotOurCallback: () => void }, attempt: Promise<boolean>) {
  iframe.loadsSomethingThatIsNotOurCallback();
  await vi.advanceTimersByTimeAsync(1_100);
  await attempt.catch(() => undefined);
}

describe("giving up on a refused silent sign-in", () => {
  it("gives up about a second after the iframe loads, not twenty", async () => {
    // The regression test for the defect. Twenty seconds of "Signing you in…" is what a
    // person saw on every reload in a browser that blocks third-party cookies.
    const { iframe, attempt } = await start();
    expect(iframe.inDocument()).toBe(true);

    iframe.loadsSomethingThatIsNotOurCallback();
    await vi.advanceTimersByTimeAsync(1_100);

    await expect(attempt).resolves.toBe(false);
  });

  it("has not given up before the iframe loads anything", async () => {
    // The grace period is triggered by `load`, not by the clock. A slow provider that
    // has not answered yet must not be treated as a refusal.
    const { iframe, attempt } = await start();

    let settled = false;
    void attempt.then(() => (settled = true));
    await vi.advanceTimersByTimeAsync(5_000);

    expect(settled).toBe(false);
    await settle(iframe, attempt);
  });

  it("still gives up if the iframe never loads at all", async () => {
    // The backstop, for a hung network or a provider that accepts and never answers.
    const { attempt } = await start();

    let settled = false;
    void attempt.then(() => (settled = true));

    await vi.advanceTimersByTimeAsync(19_000);
    expect(settled).toBe(false);

    await vi.advanceTimersByTimeAsync(2_000);
    await expect(attempt).resolves.toBe(false);
    expect(settled).toBe(true);
  });

  it("takes the iframe back out of the document", async () => {
    // One hidden iframe per failed attempt, accumulating for the life of the page, is
    // the shape of leak nobody notices until a tab is left open all day.
    const { iframe, attempt } = await start();

    iframe.loadsSomethingThatIsNotOurCallback();
    await vi.advanceTimersByTimeAsync(1_100);
    await attempt;

    expect(iframe.inDocument()).toBe(false);
  });
});

describe("where the endpoints come from", () => {
  it("sends the iframe to the discovery document's authorization_endpoint", async () => {
    // The pin against concatenation: this URL's path is `/oauth2/authorize`, which no
    // `${issuer}/v1/authorize` template can produce. If this fails with a `/v1/` URL,
    // the Okta shape is back.
    const { iframe, attempt } = await start();
    expect(iframe.frame.src.startsWith(`${ISSUER}/oauth2/authorize?`)).toBe(true);
    await settle(iframe, attempt);
  });
});

describe("a callback that does arrive", () => {
  /** A token endpoint that answers. `silentSignIn` exchanges the code before returning,
   *  and without this the exchange is a real network call. */
  function stubTokenEndpoint() {
    stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ access_token: "header.eyJzdWIiOiJhIn0.sig", expires_in: 3600 }),
    }));
  }

  // Every case here dispatches `load` as well as the message, because that is what
  // actually happens: the callback is a real document in the frame, so it fires `load`
  // like any other. `main.tsx` posts before React mounts and therefore before that
  // event — the grace period exists so the ordering never has to be relied on, and
  // these assert that a load arriving alongside a good outcome does not cancel it.

  it("wins, and does not wait out the grace period to do it", async () => {
    stubTokenEndpoint();
    const { iframe, attempt } = await start();

    iframe.postsCallback(`?code=abc&state=${iframe.state()}`);
    iframe.loadsSomethingThatIsNotOurCallback();

    // Nothing like the grace period, let alone the timeout.
    await vi.advanceTimersByTimeAsync(50);
    await expect(attempt).resolves.toBe(true);
  });

  it("wins even when the load event gets there first", async () => {
    stubTokenEndpoint();
    const { iframe, attempt } = await start();

    iframe.loadsSomethingThatIsNotOurCallback();
    iframe.postsCallback(`?code=abc&state=${iframe.state()}`);

    await vi.advanceTimersByTimeAsync(50);
    await expect(attempt).resolves.toBe(true);
  });

  it("ignores a message from another origin", async () => {
    // The frame's content is ours; anything else posting here is somebody else's page.
    const { iframe, attempt } = await start();

    window.dispatchEvent(
      new MessageEvent("message", {
        data: { type: "carnet-auth-callback", search: "?code=evil&state=x" },
        origin: "https://attacker.example",
      }),
    );

    iframe.loadsSomethingThatIsNotOurCallback();
    await vi.advanceTimersByTimeAsync(1_100);

    await expect(attempt).resolves.toBe(false);
  });

  it("refuses a callback whose state is not the one this tab asked for", async () => {
    // Not ceremony: a mismatch means this is not the response this tab asked for, and
    // continuing would be exchanging a code somebody else obtained.
    const { iframe, attempt } = await start();

    iframe.postsCallback("?code=abc&state=not-the-one");
    iframe.loadsSomethingThatIsNotOurCallback();
    await vi.advanceTimersByTimeAsync(1_100);

    await expect(attempt).resolves.toBe(false);
  });
});

describe("where signing in sends you back to", () => {
  it("returns to the page the gate appeared over, not to a fixed one", async () => {
    // Observed in a browser: reloading `/agents/minimal` signed you in and dropped you
    // on `/agents`, because the gate passed a hardcoded "/agents" to `signIn`. The
    // default is the current path, and the argument existed only to override it.
    const { signIn } = await import("./auth");
    const assign = vi.fn();
    vi.stubGlobal("location", {
      origin: window.location.origin,
      pathname: "/agents/minimal",
      search: "",
      assign,
    });

    void signIn();
    for (let tick = 0; tick < 100 && assign.mock.calls.length === 0; tick++) {
      await vi.advanceTimersByTimeAsync(0);
    }

    expect(sessionStorage.getItem("carnet.pkce.return")).toBe("/agents/minimal");
  });

  it("still honours an explicit destination when one is given", async () => {
    const { signIn } = await import("./auth");
    const assign = vi.fn();
    vi.stubGlobal("location", {
      origin: window.location.origin,
      pathname: "/agents/minimal",
      search: "",
      assign,
    });

    void signIn("/agents");
    for (let tick = 0; tick < 100 && assign.mock.calls.length === 0; tick++) {
      await vi.advanceTimersByTimeAsync(0);
    }

    expect(sessionStorage.getItem("carnet.pkce.return")).toBe("/agents");
  });
});
