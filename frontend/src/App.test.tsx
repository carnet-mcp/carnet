/** The gate, the callback, and the sign-in screen — 247 lines no test had ever named.
 *
 * `lib/auth.ts` is 687 lines with its own suite; the components that *drive* it had
 * none, and they are the whole sign-in path a person actually sees:
 *
 *   - **Gate tries silence first.** A page load boots a silent renewal rather than
 *     showing a login button, because the token is in memory and every reload starts
 *     with nothing — a prompt on every refresh is how a token ends up in localStorage.
 *   - **SignIn is what is left when that fails**, with the reason if there was one, and
 *     its button returns to wherever the gate appeared over — `signIn()` with no
 *     argument, because passing "/agents" once threw away the deep link somebody
 *     reloaded.
 *   - **Callback exchanges the code and gets out of the way**, and when it cannot, the
 *     failure is rendered in the error's own words with a way back.
 *
 * `lib/auth` is the mocked seam — these components are its consumers, exactly as pages
 * mock `lib/api`.
 */

import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Session } from "./lib/auth";

const auth = vi.hoisted(() => {
  const listeners = new Set<() => void>();
  let session: Session = { state: "unknown" };
  return {
    listeners,
    current: () => session,
    set(next: Session) {
      session = next;
      listeners.forEach((fn) => fn());
    },
    boot: vi.fn(() => Promise.resolve()),
    completeSignIn: vi.fn<() => Promise<string>>(),
    signIn: vi.fn(() => Promise.resolve() as Promise<never>),
    signOut: vi.fn(),
  };
});

vi.mock("./lib/auth", () => ({
  CALLBACK_PATH: "/login/callback",
  subscribe: (fn: () => void) => {
    auth.listeners.add(fn);
    return () => auth.listeners.delete(fn);
  },
  current: auth.current,
  boot: auth.boot,
  completeSignIn: auth.completeSignIn,
  signIn: auth.signIn,
  signOut: auth.signOut,
}));

vi.mock("./lib/api", async () => {
  const actual = await vi.importActual<typeof import("./lib/api")>("./lib/api");
  return { ...actual, api: { me: vi.fn(), listAgents: vi.fn() } };
});

import App from "./App";
import { api } from "./lib/api";

beforeEach(() => {
  auth.set({ state: "unknown" });
  auth.boot.mockClear();
  auth.signIn.mockClear();
  auth.completeSignIn.mockReset();
  vi.mocked(api.me).mockResolvedValue({
    principal: "user:u_priya",
    kind: "user",
    email: "priya@example.com",
    display_name: "Priya",
    admin: false,
  });
  vi.mocked(api.listAgents).mockResolvedValue([]);
});

afterEach(() => {
  window.history.replaceState(null, "", "/");
});

describe("Gate", () => {
  it("tries silently first: a spinner and a boot, not a login button", () => {
    render(<App />);

    expect(screen.getByText("Signing you in…")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument();
    expect(auth.boot).toHaveBeenCalledOnce();
  });

  it("renders the app once there is a principal", async () => {
    render(<App />);
    // The transition the gate exists for: boot succeeded while the spinner showed.
    act(() => auth.set({ state: "in", claims: { email: "priya@example.com" } }));

    // "/" redirects to /agents; the empty list is the proof the page inside rendered.
    expect(
      await screen.findByText("No agents here yet"),
    ).toBeInTheDocument();
  });
});

describe("SignIn", () => {
  it("is what is left when silence fails, with the reason if there was one", () => {
    auth.set({ state: "out", reason: "your session at the provider has ended" });
    render(<App />);

    expect(screen.getByText("You were signed out")).toBeInTheDocument();
    expect(
      screen.getByText("your session at the provider has ended"),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
  });

  it("says nothing about being signed out when there is no reason", () => {
    auth.set({ state: "out", reason: "" });
    render(<App />);

    expect(screen.queryByText("You were signed out")).not.toBeInTheDocument();
  });

  it("starts the redirect with no argument, so it returns to this page, and locks the button", async () => {
    auth.set({ state: "out", reason: "" });
    render(<App />);

    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    // No argument: `signIn` defaults to the current path. Passing "/agents" here once
    // dropped a reloaded deep link onto the list page.
    expect(auth.signIn).toHaveBeenCalledWith();
    expect(screen.getByRole("button", { name: "Taking you to sign in…" })).toBeDisabled();
  });
});

describe("Callback", () => {
  it("exchanges the code and navigates to where the person was going", async () => {
    auth.completeSignIn.mockResolvedValue("/agents");
    auth.set({ state: "in", claims: { email: "priya@example.com" } });
    window.history.replaceState(null, "", "/login/callback?code=abc&state=xyz");

    render(<App />);

    expect(
      await screen.findByText("No agents here yet"),
    ).toBeInTheDocument();
    expect(auth.completeSignIn).toHaveBeenCalledOnce();
    // `replace: true` — the callback must not be in history for Back to land on.
    expect(window.location.pathname).toBe("/agents");
  });

  it("renders the exchange's failure in its own words, with a way back", async () => {
    auth.completeSignIn.mockRejectedValue(
      new Error("the state on this callback matches no sign-in this browser started"),
    );
    window.history.replaceState(null, "", "/login/callback?code=abc&state=forged");

    render(<App />);

    expect(await screen.findByText("Sign-in did not complete")).toBeInTheDocument();
    expect(
      screen.getByText(
        "the state on this callback matches no sign-in this browser started",
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Try again" })).toHaveAttribute(
      "href",
      "/agents",
    );
  });
});

describe("NotFound", () => {
  it("offers the way back for a path that matches nothing", async () => {
    auth.set({ state: "in", claims: {} });
    window.history.replaceState(null, "", "/no-such-page");

    render(<App />);

    expect(await screen.findByText("No such page")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to your agents" })).toHaveAttribute(
      "href",
      "/agents",
    );
  });
});

describe("the gate and the callback compose", () => {
  it("keeps the callback outside the gate — no sign-in screen over a code exchange", async () => {
    // Session is "out": anywhere else this renders SignIn. The callback route must
    // not, or the person completing a sign-in would be told to sign in.
    auth.set({ state: "out", reason: "" });
    auth.completeSignIn.mockReturnValue(new Promise(() => {}));
    window.history.replaceState(null, "", "/login/callback?code=abc&state=xyz");

    render(<App />);

    expect(screen.getByText("Finishing sign-in…")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument();
    await waitFor(() => expect(auth.completeSignIn).toHaveBeenCalled());
  });
});
