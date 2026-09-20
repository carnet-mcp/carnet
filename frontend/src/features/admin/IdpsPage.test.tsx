/** The identity-provider screen, and the three things it must not get wrong.
 *
 *   - **it pre-empts nothing.** One statement of what a valid provider is, on the
 *     server, read by two doors; every refusal here is that sentence verbatim — including
 *     the 409 for an issuer that would make a token ambiguous between two tenants.
 *   - **discovery fills the key set and never overrides what was typed.** The server has
 *     already refused a document whose issuer differs; what comes back is applied.
 *   - **removing the provider you signed in through is refused in the server's words**,
 *     and the confirmation names the consequence rather than asking "are you sure".
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return {
    ...actual,
    api: {
      listIdps: vi.fn(),
      registerIdp: vi.fn(),
      removeIdp: vi.fn(),
      discoverIdp: vi.fn(),
    },
  };
});

import IdpsPage from "./IdpsPage";
import { api, ApiError } from "../../lib/api";
import type { IdpEntry } from "../../lib/types";

function provider(overrides: Partial<IdpEntry> = {}): IdpEntry {
  return {
    issuer: "https://acme.okta.example",
    jwks_uri: "https://acme.okta.example/oauth2/v1/keys",
    audience: "api://default",
    discriminator_claim: null,
    discriminator_value: null,
    subject_claim: "sub",
    email_claim: "email",
    groups_claim: null,
    allowed_domains: ["acme.com"],
    enabled: true,
    ...overrides,
  };
}

function show(providers: IdpEntry[] = [provider()]) {
  vi.mocked(api.listIdps).mockResolvedValue(providers);
  return render(
    <MemoryRouter>
      <IdpsPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn === "function" && "mockReset" in fn) vi.mocked(fn).mockReset();
  }
});

describe("the list", () => {
  it("shows what each provider routes on, vouches for and maps", async () => {
    show([
      provider(),
      provider({
        issuer: "https://accounts.google.example",
        discriminator_claim: "hd",
        discriminator_value: "acme.com",
        email_claim: "preferred_username",
        groups_claim: "groups",
        enabled: false,
      }),
    ]);

    expect(await screen.findByText("https://acme.okta.example")).toBeInTheDocument();
    expect(screen.getByText(/Routes on the whole issuer\. Vouches for acme\.com/)).toBeInTheDocument();
    expect(screen.getByText(/Routes on hd = acme\.com/)).toBeInTheDocument();
    expect(screen.getByText(/email: preferred_username/)).toBeInTheDocument();
    expect(screen.getByText(/groups: \(the directory decides nothing\)/)).toBeInTheDocument();
    expect(screen.getByText("disabled")).toBeInTheDocument();
  });

  it("says nobody can sign in when there is none", async () => {
    show([]);

    expect(await screen.findByText("No identity provider registered")).toBeInTheDocument();
    expect(screen.getByText(/Nobody can sign in until one is/)).toBeInTheDocument();
  });
});

describe("registering", () => {
  it("sends the nine flags as a body, with the domains split and the blanks as null", async () => {
    vi.mocked(api.registerIdp).mockResolvedValue({
      provider: provider({ issuer: "https://login.example.com/t1/v2.0" }),
      replaced: false,
    });
    show();

    await userEvent.type(
      await screen.findByPlaceholderText("https://acme.okta.com"),
      "https://login.example.com/t1/v2.0",
    );
    await userEvent.type(
      screen.getByPlaceholderText("https://acme.okta.com/oauth2/v1/keys"),
      "https://login.example.com/t1/discovery/v2.0/keys",
    );
    await userEvent.type(screen.getByPlaceholderText("api://default"), "api://carnet");
    await userEvent.type(screen.getByPlaceholderText("acme.com, acme.co.uk"), "acme.com, , acme.co.uk ");
    await userEvent.clear(screen.getByLabelText("Email claim"));
    await userEvent.type(screen.getByLabelText("Email claim"), "preferred_username");
    await userEvent.type(screen.getByLabelText("Groups claim"), "groups");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() =>
      expect(api.registerIdp).toHaveBeenCalledWith({
        issuer: "https://login.example.com/t1/v2.0",
        jwks_uri: "https://login.example.com/t1/discovery/v2.0/keys",
        audience: "api://carnet",
        discriminator_claim: null,
        discriminator_value: null,
        subject_claim: "sub",
        email_claim: "preferred_username",
        groups_claim: "groups",
        allowed_domains: ["acme.com", "acme.co.uk"],
      }),
    );
    expect(await screen.findByText(/Registered https:\/\/login\.example\.com\/t1\/v2\.0/)).toBeInTheDocument();
  });

  it("says when it replaced a row, because the claim mappings were reset with it", async () => {
    vi.mocked(api.registerIdp).mockResolvedValue({ provider: provider(), replaced: true });
    show();

    await userEvent.type(await screen.findByPlaceholderText("https://acme.okta.com"), "https://acme.okta.example");
    await userEvent.type(screen.getByPlaceholderText("https://acme.okta.com/oauth2/v1/keys"), "https://acme.okta.example/keys");
    await userEvent.type(screen.getByPlaceholderText("api://default"), "api://default");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    expect(await screen.findByText(/Replaced https:\/\/acme\.okta\.example\. Every claim mapping is now what this form said/)).toBeInTheDocument();
  });

  it("renders the server's refusal verbatim, including the 409 for an ambiguous issuer", async () => {
    vi.mocked(api.registerIdp).mockRejectedValue(
      new ApiError(
        409,
        "https://accounts.google.example is already registered for tenant other-tenant " +
          "without a discriminator; a token from it would be ambiguous.",
      ),
    );
    show();

    await userEvent.type(await screen.findByPlaceholderText("https://acme.okta.com"), "https://accounts.google.example");
    await userEvent.type(screen.getByPlaceholderText("https://acme.okta.com/oauth2/v1/keys"), "https://accounts.google.example/keys");
    await userEvent.type(screen.getByPlaceholderText("api://default"), "123.apps");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    expect(await screen.findByText(/a token from it would be ambiguous/)).toBeInTheDocument();
  });

  it("refuses nothing itself: a wildcard domain goes to the server, whose sentence comes back", async () => {
    vi.mocked(api.registerIdp).mockRejectedValue(
      new ApiError(400, "'*' is not an allowed email domain for 'https://acme.okta.example'. Name the domains this customer owns."),
    );
    show();

    await userEvent.type(await screen.findByPlaceholderText("https://acme.okta.com"), "https://acme.okta.example");
    await userEvent.type(screen.getByPlaceholderText("https://acme.okta.com/oauth2/v1/keys"), "https://acme.okta.example/keys");
    await userEvent.type(screen.getByPlaceholderText("api://default"), "api://default");
    await userEvent.type(screen.getByPlaceholderText("acme.com, acme.co.uk"), "*");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() =>
      expect(api.registerIdp).toHaveBeenCalledWith(expect.objectContaining({ allowed_domains: ["*"] })),
    );
    expect(await screen.findByText(/Name the domains this customer owns/)).toBeInTheDocument();
  });
});

describe("looking a provider up", () => {
  it("fills the key set from the discovery document and lists the claims it emits", async () => {
    vi.mocked(api.discoverIdp).mockResolvedValue({
      issuer: "https://acme.okta.example",
      jwks_uri: "https://acme.okta.example/oauth2/v1/keys",
      claims_supported: ["sub", "email", "groups"],
    });
    show();

    await userEvent.type(await screen.findByPlaceholderText("https://acme.okta.com"), "https://acme.okta.example");
    await userEvent.click(screen.getByRole("button", { name: "Look it up" }));

    await waitFor(() => expect(api.discoverIdp).toHaveBeenCalledWith("https://acme.okta.example"));
    expect(await screen.findByText(/listed under Claims/)).toBeInTheDocument();
    // The claims land in the hint beside the three inputs that need them.
    expect(screen.getByText(/The provider says it emits: sub, email, groups/)).toBeInTheDocument();
    expect(screen.getByPlaceholderText("https://acme.okta.com/oauth2/v1/keys")).toHaveValue(
      "https://acme.okta.example/oauth2/v1/keys",
    );
  });

  it("renders a provider that serves no discovery as the server's sentence, and the form stays", async () => {
    vi.mocked(api.discoverIdp).mockRejectedValue(
      new ApiError(502, "could not fetch https://idp.corp.invalid/.well-known/openid-configuration: no route. If the provider serves no discovery document, enter its JWKS URL by hand."),
    );
    show();

    await userEvent.type(await screen.findByPlaceholderText("https://acme.okta.com"), "https://idp.corp.invalid");
    await userEvent.click(screen.getByRole("button", { name: "Look it up" }));

    expect(await screen.findByText(/enter its JWKS URL by hand/)).toBeInTheDocument();
    expect(screen.getByPlaceholderText("https://acme.okta.com/oauth2/v1/keys")).toHaveValue("");
  });
});

describe("removing", () => {
  it("names the consequence, then sends the issuer and the discriminator value", async () => {
    vi.mocked(api.removeIdp).mockResolvedValue({
      issuer: "https://accounts.google.example",
      discriminator_value: "acme.com",
      removed: true,
    });
    show([
      provider(),
      provider({
        issuer: "https://accounts.google.example",
        discriminator_claim: "hd",
        discriminator_value: "acme.com",
      }),
    ]);

    const google = (await screen.findByText("https://accounts.google.example")).closest(".row")!;
    await userEvent.click(google.querySelector("button")!);

    expect(await screen.findByText(/locked out at their next sign-in/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Remove" }));

    await waitFor(() =>
      expect(api.removeIdp).toHaveBeenCalledWith("https://accounts.google.example", "acme.com"),
    );
  });

  it("renders the refusal for the provider you signed in through, verbatim", async () => {
    vi.mocked(api.removeIdp).mockRejectedValue(
      new ApiError(
        400,
        "you signed in through https://acme.okta.example, so removing it would lock this tenant out — including you, at your next sign-in. Register the provider that replaces it first.",
      ),
    );
    show();

    await userEvent.click(await screen.findByRole("button", { name: "Remove…" }));
    await userEvent.click(screen.getByRole("button", { name: "Remove" }));

    expect(await screen.findByText(/would lock this tenant out/)).toBeInTheDocument();
    expect(api.listIdps).toHaveBeenCalledTimes(1);
  });
});
