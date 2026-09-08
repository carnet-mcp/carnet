/** The consent page. What is worth asserting:
 *
 *    - **the page decides nothing about URLs.** It navigates to what the server answers,
 *      and its buttons are disabled until the server-returned list contains the
 *      request's `redirect_uri`
 *    - **the decision goes to the server with the request's parameters**, approve and
 *      deny alike — a denial is a redirect too, and the server is the one that knows
 *      where
 *    - **a refusal is a sentence on the page**, not a redirect
 */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return { ...actual, api: { oauthClient: vi.fn(), oauthConsent: vi.fn() } };
});

import AuthorizePage from "./AuthorizePage";
import { ApiError, api } from "../../lib/api";

const CLIENT = {
  client_id: "oc_0123456789abcdef",
  client_name: "Claude",
  client_uri: "https://claude.ai",
  redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
};

const REQUEST = {
  client_id: CLIENT.client_id,
  redirect_uri: "https://claude.ai/api/mcp/auth_callback",
  state: "xyz",
  response_type: "code",
  code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  code_challenge_method: "S256",
  resource: "https://ship.acme.com/api/mcp",
};

function show(request: Record<string, string> = REQUEST) {
  const query = new URLSearchParams(request).toString();
  return render(
    <MemoryRouter initialEntries={[`/oauth/authorize?${query}`]}>
      <Routes>
        <Route path="/oauth/authorize" element={<AuthorizePage />} />
      </Routes>
    </MemoryRouter>,
  );
}

const assign = vi.fn();

beforeEach(() => {
  vi.mocked(api.oauthClient).mockReset();
  vi.mocked(api.oauthConsent).mockReset();
  assign.mockReset();
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { ...window.location, assign },
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("what the page shows", () => {
  it("names the client, where it sends you back, and that it acts as you", async () => {
    vi.mocked(api.oauthClient).mockResolvedValue(CLIENT);
    show();

    expect(await screen.findByRole("heading", { name: "Claude" })).toBeInTheDocument();
    expect(screen.getByText(/sends you back to claude\.ai/)).toBeInTheDocument();
    expect(screen.getByText("as you", { selector: "strong" })).toBeInTheDocument();
    expect(screen.getByText("https://claude.ai")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Deny" })).toBeEnabled();
    expect(api.oauthClient).toHaveBeenCalledWith(CLIENT.client_id);
  });

  it("refuses to offer a decision when the redirect_uri is not one the client registered", async () => {
    vi.mocked(api.oauthClient).mockResolvedValue(CLIENT);
    show({ ...REQUEST, redirect_uri: "https://evil.example/cb" });

    expect(await screen.findByText("This request cannot be approved")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    expect(assign).not.toHaveBeenCalled();
  });

  it("renders the server's refusal for an unknown client", async () => {
    vi.mocked(api.oauthClient).mockRejectedValue(new ApiError(400, "no client is registered under that id."));
    show();
    expect(await screen.findByText(/no client is registered/)).toBeInTheDocument();
  });
});

describe("the decision", () => {
  it("sends approval with the request's parameters and goes where the server says", async () => {
    vi.mocked(api.oauthClient).mockResolvedValue(CLIENT);
    vi.mocked(api.oauthConsent).mockResolvedValue({
      redirect_to: "https://claude.ai/api/mcp/auth_callback?code=abc&state=xyz",
    });
    show();
    await screen.findByRole("button", { name: "Approve" });

    fireEvent.change(screen.getByLabelText(/Token name/), { target: { value: " laptop " } });
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() =>
      expect(assign).toHaveBeenCalledWith(
        "https://claude.ai/api/mcp/auth_callback?code=abc&state=xyz",
      ),
    );
    expect(api.oauthConsent).toHaveBeenCalledWith({
      client_id: CLIENT.client_id,
      redirect_uri: REQUEST.redirect_uri,
      approve: true,
      state: "xyz",
      response_type: "code",
      code_challenge: REQUEST.code_challenge,
      code_challenge_method: "S256",
      resource: REQUEST.resource,
      scope: null,
      token_name: "laptop",
    });
  });

  it("sends a denial through the server too, because the server knows where to bounce", async () => {
    vi.mocked(api.oauthClient).mockResolvedValue(CLIENT);
    vi.mocked(api.oauthConsent).mockResolvedValue({
      redirect_to: "https://claude.ai/api/mcp/auth_callback?error=access_denied&state=xyz",
    });
    show();
    await screen.findByRole("button", { name: "Deny" });

    fireEvent.click(screen.getByRole("button", { name: "Deny" }));

    await waitFor(() => expect(assign).toHaveBeenCalled());
    expect(vi.mocked(api.oauthConsent).mock.calls[0][0]).toMatchObject({
      approve: false,
      token_name: null,
    });
  });

  it("shows a refusal on the page and redirects nowhere", async () => {
    vi.mocked(api.oauthClient).mockResolvedValue(CLIENT);
    vi.mocked(api.oauthConsent).mockRejectedValue(
      new ApiError(400, "redirect_uri is not one this client registered."),
    );
    show();
    await screen.findByRole("button", { name: "Approve" });

    fireEvent.click(screen.getByRole("button", { name: "Approve" }));

    expect(await screen.findByText(/not one this client registered/)).toBeInTheDocument();
    expect(assign).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Approve" })).toBeEnabled();
  });
});
