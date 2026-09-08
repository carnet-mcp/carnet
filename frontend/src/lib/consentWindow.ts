/** Running a consent flow in a popup, so the page that started it survives.
 *
 * **This exists because of a bug found by using the thing.** Connecting an account signed
 * you out of the application, every time.
 *
 * The mechanism, and none of it is 7b's fault except the part that triggers it:
 *
 *   1. This app's own token is held **in memory only** — deliberately, so it is never in
 *      storage a script could read. `auth.ts` argues that at length.
 *   2. Every screen before 7b was click-through: React Router, never a real page load. So
 *      the in-memory token was never actually tested by anything but a manual refresh.
 *   3. A consent flow **must** leave the origin — that is what OAuth is. Navigating to
 *      the provider destroys the page and the token with it.
 *   4. Coming back, the app tries to renew silently, in a hidden iframe, using the
 *      provider's cookie as a **third-party** cookie. Browsers are taking that away, and
 *      `auth.ts` records it already failing in Brave and in stock headless Chromium.
 *   5. So the renewal fails and you land on the sign-in screen.
 *
 * The connection itself was always fine — the server did the work and the token was
 * sealed. What broke was the *session of the page that asked for it*, and it broke on
 * every single use, which makes a working feature feel like a broken one.
 *
 * ## Why a popup rather than fixing the session
 *
 * Because the popup does not touch the session design at all. The page that started the
 * flow never unloads, so its token is still there when the popup closes. The two real
 * fixes — making a failed boot redirect instead of showing a screen, or moving the
 * session into an HttpOnly cookie — are both deliberately deferred with reasons written
 * down in `auth.ts` and `DEFERRED.md`, and both are larger than this whole step.
 *
 * It also changes **no security property**. The popup goes to the provider and comes back
 * to our own callback; the token still never touches any browser, and `state` is still
 * what binds the callback to the person. The opener learns one thing: that it finished.
 *
 * ## The two things this has to get right
 *
 * **Open the window synchronously.** A browser only allows `window.open` inside the click
 * that a person actually made. Waiting for the server to mint the URL first breaks that
 * chain and the popup is blocked. So it opens blank, immediately, and is pointed at the
 * provider once the URL arrives.
 *
 * **Fall back rather than fail.** A blocked popup returns null, and then this does what it
 * did before — a full-page navigation. That reintroduces the sign-out papercut, which is
 * strictly better than a Connect button that does nothing.
 */

export const CONSENT_MESSAGE = "carnet-consent-done";

/** What the popup tells its opener, straight off the query string the server redirected
 *  with. Deliberately not a token, an account name, or anything else — the opener reloads
 *  from the API rather than trusting a message. */
export interface ConsentOutcome {
  connected: string;
  failed: string;
}

/** Handle this page load if it is a consent popup coming back. See `main.tsx`.
 *
 *  Mirrors `postCallbackToOpener` exactly, and runs in the same place and for the same
 *  reason: mounting the application inside a window that is about to close is work nobody
 *  sees, and here it would additionally boot a second silent sign-in — inside a popup,
 *  where it would fail and render a sign-in screen for a quarter of a second before
 *  closing.
 *
 *  Returns true when it handled the load and the caller must render nothing. */
export function closeConsentPopup(): boolean {
  const params = new URLSearchParams(window.location.search);
  const connected = params.get("connected") ?? "";
  const failed = params.get("failed") ?? "";

  // `window.opener` alone is not enough — any window opened by another has one. It is the
  // pairing with an outcome this app put on the URL that makes this specific.
  if (!window.opener || (!connected && !failed)) return false;

  window.opener.postMessage(
    { type: CONSENT_MESSAGE, connected, failed },
    window.location.origin,
  );
  window.close();
  return true;
}

/** Run a consent flow in a popup. Resolves with the outcome, or null if it was abandoned.
 *
 *  `authorizeUrl` is a function rather than a string because of the synchronous-open rule
 *  above: the window has to exist before the server has answered, so this opens it, then
 *  asks, then points it.
 *
 *  Rejects only if the server refused to start the flow. A person who closes the popup,
 *  or who is refused by the provider, is not an error — the first resolves null and the
 *  second comes back as `failed`. */
export function runConsent(
  authorizeUrl: () => Promise<string>,
  { fallback, signal }: { fallback: (url: string) => void; signal?: AbortSignal },
): Promise<ConsentOutcome | null> {
  // Synchronously, inside the click. See the module docstring.
  const popup = window.open("", "carnet-consent", "width=620,height=780");

  if (!popup) {
    // Blocked. Do what this did before — a full-page navigation, which works and costs
    // the session. Better than a button that appears to do nothing.
    return authorizeUrl().then((url) => {
      fallback(url);
      return null;
    });
  }

  return authorizeUrl().then(
    (url) => {
      popup.location.href = url;
      return waitFor(popup, signal);
    },
    (error: unknown) => {
      // The server refused — no consent flow configured, a bad `return_to`. Close the
      // blank window rather than leaving somebody staring at one.
      popup.close();
      throw error;
    },
  );
}

/** Wait for the popup to report back, to be closed, or for the caller to give up.
 *
 *  **`signal` is not optional in practice, and leaving it out was a leak** — found when
 *  one test's abandoned flow started answering another test's message. A consent flow can
 *  legitimately take minutes, so there is no timeout to fall back on: without an abort,
 *  a person who clicks Connect and then navigates away leaves a poll running for the life
 *  of the tab and a listener that calls back into a component which no longer exists.
 *
 *  The test suite noticed first because it unmounts between cases, which is exactly what
 *  the router does. */
function waitFor(popup: Window, signal?: AbortSignal): Promise<ConsentOutcome | null> {
  return new Promise((resolve) => {
    let done = false;

    const finish = (outcome: ConsentOutcome | null) => {
      if (done) return;
      done = true;
      window.removeEventListener("message", onMessage);
      signal?.removeEventListener("abort", onAbort);
      clearInterval(watch);
      resolve(outcome);
    };

    // Null, not an outcome: the caller has gone, and nothing is known about what the
    // person did in the popup. It stays open — closing somebody's consent screen because
    // they clicked a link in the other tab would be the rudest possible cleanup.
    const onAbort = () => finish(null);

    function onMessage(event: MessageEvent) {
      // Same-origin only. The popup visits a **third party** in the middle of this, and
      // that third party can post to its opener — so a message whose origin is not ours
      // is a provider, or something pretending to be one, and is ignored.
      if (event.origin !== window.location.origin) return;
      const data = event.data as { type?: string; connected?: string; failed?: string };
      if (data?.type !== CONSENT_MESSAGE) return;
      finish({ connected: data.connected ?? "", failed: data.failed ?? "" });
    }

    window.addEventListener("message", onMessage);
    if (signal?.aborted) return finish(null);
    signal?.addEventListener("abort", onAbort);

    // **Somebody closing the popup is the ordinary way this ends**, not an edge case:
    // they change their mind at the provider's screen and hit the X. Without this the
    // button spins forever, which is the failure people report as "it hung".
    const watch = setInterval(() => {
      if (popup.closed) finish(null);
    }, 400);
  });
}
