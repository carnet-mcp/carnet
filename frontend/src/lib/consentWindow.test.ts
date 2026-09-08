/** The popup machinery, tested at the two edges its docstring argues about.
 *
 * The module exists because connecting an account signed you out every time; what is
 * pinned here is the mechanics that keep that fixed and safe:
 *
 *   - **the window opens synchronously**, before the server has answered — inside the
 *     click is the only place a browser allows it.
 *   - **a blocked popup falls back to navigation** rather than a button that does
 *     nothing.
 *   - **only a same-origin message ends the wait.** The popup visits a third party in
 *     the middle of the flow, and that third party can post to its opener.
 *   - **closing the popup is the ordinary ending**, resolving null rather than hanging.
 *   - **an abort leaves the popup open** — closing somebody's consent screen because
 *     they clicked a link in the other tab would be the rudest possible cleanup.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { CONSENT_MESSAGE, closeConsentPopup, runConsent } from "./consentWindow";

type FakePopup = {
  location: { href: string };
  close: ReturnType<typeof vi.fn>;
  closed: boolean;
};

function fakePopup(): FakePopup {
  return { location: { href: "" }, close: vi.fn(), closed: false };
}

function arrive(data: unknown, origin = window.location.origin) {
  window.dispatchEvent(new MessageEvent("message", { origin, data }));
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  (window as { opener: unknown }).opener = null;
  window.history.replaceState(null, "", "/");
});

describe("closeConsentPopup", () => {
  it("does nothing for a page that is not a consent popup coming back", () => {
    // No opener, no outcome on the URL — an ordinary page load.
    expect(closeConsentPopup()).toBe(false);
  });

  it("needs the outcome this app put on the URL, not just an opener", () => {
    // Any window opened by another has an opener; the pairing is what makes it ours.
    (window as { opener: unknown }).opener = { postMessage: vi.fn() };

    expect(closeConsentPopup()).toBe(false);
  });

  it("reports the outcome to its opener, same-origin, and closes", () => {
    const postMessage = vi.fn();
    (window as { opener: unknown }).opener = { postMessage };
    window.history.replaceState(null, "", "/?connected=acme");
    const close = vi.spyOn(window, "close").mockImplementation(() => {});

    expect(closeConsentPopup()).toBe(true);
    expect(postMessage).toHaveBeenCalledWith(
      { type: CONSENT_MESSAGE, connected: "acme", failed: "" },
      window.location.origin,
    );
    expect(close).toHaveBeenCalled();
  });
});

describe("runConsent", () => {
  it("opens the window before the server has answered, then points it", async () => {
    const popup = fakePopup();
    const open = vi.spyOn(window, "open").mockReturnValue(popup as unknown as Window);
    let mint: (url: string) => void = () => {};
    const authorizeUrl = () => new Promise<string>((resolve) => (mint = resolve));

    const outcome = runConsent(authorizeUrl, { fallback: vi.fn() });

    // Already open, still blank: the synchronous-open rule observed from outside.
    expect(open).toHaveBeenCalledOnce();
    expect(popup.location.href).toBe("");

    mint("https://provider.example/authorize?state=abc");
    await Promise.resolve();
    expect(popup.location.href).toBe("https://provider.example/authorize?state=abc");

    arrive({ type: CONSENT_MESSAGE, connected: "acme", failed: "" });
    await expect(outcome).resolves.toEqual({ connected: "acme", failed: "" });
  });

  it("ignores a message from another origin — the provider can post to its opener", async () => {
    vi.useFakeTimers();
    const popup = fakePopup();
    vi.spyOn(window, "open").mockReturnValue(popup as unknown as Window);

    const outcome = runConsent(() => Promise.resolve("https://provider.example/a"), {
      fallback: vi.fn(),
    });
    await vi.advanceTimersByTimeAsync(0);

    arrive({ type: CONSENT_MESSAGE, connected: "evil", failed: "" }, "https://provider.example");

    // The forged message did not end the wait; the person closing the popup does.
    popup.closed = true;
    await vi.advanceTimersByTimeAsync(500);
    await expect(outcome).resolves.toBeNull();
  });

  it("falls back to a full navigation when the popup is blocked", async () => {
    vi.spyOn(window, "open").mockReturnValue(null);
    const fallback = vi.fn();

    const outcome = await runConsent(
      () => Promise.resolve("https://provider.example/authorize"),
      { fallback },
    );

    expect(fallback).toHaveBeenCalledWith("https://provider.example/authorize");
    expect(outcome).toBeNull();
  });

  it("closes the blank window when the server refuses to start the flow", async () => {
    const popup = fakePopup();
    vi.spyOn(window, "open").mockReturnValue(popup as unknown as Window);

    await expect(
      runConsent(() => Promise.reject(new Error("no consent flow is configured")), {
        fallback: vi.fn(),
      }),
    ).rejects.toThrow("no consent flow is configured");
    expect(popup.close).toHaveBeenCalled();
  });

  it("resolves null on abort and leaves the popup open", async () => {
    const popup = fakePopup();
    vi.spyOn(window, "open").mockReturnValue(popup as unknown as Window);
    const controller = new AbortController();

    const outcome = runConsent(() => Promise.resolve("https://provider.example/a"), {
      fallback: vi.fn(),
      signal: controller.signal,
    });
    await Promise.resolve();
    await Promise.resolve();

    controller.abort();
    await expect(outcome).resolves.toBeNull();
    // The person may be mid-consent in that window; it is theirs to close.
    expect(popup.close).not.toHaveBeenCalled();
  });
});
