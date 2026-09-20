/** The administrators screen: a read, the command, and the sentence that says why. */

import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return { ...actual, api: { listRoles: vi.fn() } };
});

import RolesPage from "./RolesPage";
import { api } from "../../lib/api";

beforeEach(() => vi.mocked(api.listRoles).mockReset());

describe("administrators", () => {
  it("lists who holds a role by address, appointed by a principal, and offers no button", async () => {
    vi.mocked(api.listRoles).mockResolvedValue([
      {
        principal: "user:u_priya", kind: "user", id: "u_priya", email: "priya@acme.com",
        display_name: "Priya", role: "admin", granted_by: "system:bootstrap",
        granted_at: "2026-09-15T09:00:00+00:00",
      },
    ]);
    render(<MemoryRouter><RolesPage /></MemoryRouter>);

    expect(await screen.findByText("priya@acme.com")).toBeInTheDocument();
    expect(screen.getByText("system:bootstrap")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("prints the command for a change and says why it is not a button", async () => {
    vi.mocked(api.listRoles).mockResolvedValue([]);
    render(<MemoryRouter><RolesPage /></MemoryRouter>);

    expect(await screen.findByText("No platform role granted")).toBeInTheDocument();
    expect(screen.getByText(/carnet --grant-role admin/)).toBeInTheDocument();
    expect(screen.getByText(/keeps the authority after the session is gone/)).toBeInTheDocument();
    expect(screen.getByText(/The shell itself always administers/)).toBeInTheDocument();
  });
});
