/** What this module puts on the wire.
 *
 * **This file exists because of one bug.** The dev proxy claimed `/agents` and `/tools`,
 * which are also this app's own routes, so a *reload* on `/agents/abc123` matched the
 * proxy and returned the API's 401 JSON where the app should have been. Clicking to the
 * same page worked, because React Router never asks the server — which is exactly what
 * hid it, and why the handoff records "no test could have caught it" as an argument for
 * writing this kind of test rather than as a fact about testing.
 *
 * It could have been caught. Not by rendering anything: by asserting the URL.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./auth", () => ({
  bearer: vi.fn(async () => "a-token"),
  renew: vi.fn(async () => false),
  signOut: vi.fn(),
}));

import { api, ApiError, NotSignedIn } from "./api";
import { bearer, renew, signOut } from "./auth";

/** A `fetch` that records what it was asked for and answers with `body`. */
function stubFetch(body: unknown, init: { status?: number } = {}) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetcher = vi.fn(async (url: string, requestInit: RequestInit = {}) => {
    calls.push({ url, init: requestInit });
    return {
      ok: (init.status ?? 200) < 400,
      status: init.status ?? 200,
      statusText: "",
      json: async () => body,
    } as unknown as Response;
  });
  vi.stubGlobal("fetch", fetcher);
  return calls;
}

beforeEach(() => {
  vi.mocked(bearer).mockResolvedValue("a-token");
  vi.mocked(renew).mockResolvedValue(false);
});

describe("every call goes under /api", () => {
  // The regression test for the collision. Each of these paths is ALSO a route this app
  // owns, so an unprefixed request is one the server answers and the app never sees.
  // `expected` before `call` so the test name reads as the assertion rather than as a
  // stringified arrow function.
  it.each([
    ["listAgents", "/api/agents", () => api.listAgents()],
    ["getAgent", "/api/agents/minimal", () => api.getAgent("minimal")],
    ["listTools", "/api/tools", () => api.listTools()],
    ["agentAccess", "/api/agents/minimal/access", () => api.agentAccess("minimal")],
    ["deleteAgent", "/api/agents/minimal", () => api.deleteAgent("minimal")],
    ["myTokens", "/api/me/tokens", () => api.myTokens()],
    [
      "shareAgent",
      "/api/agents/minimal/grants/user/u_1fbb",
      () => api.shareAgent("minimal", "user", "u_1fbb", "editor"),
    ],
    [
      "unshareAgent",
      "/api/agents/minimal/grants/group/g_6f5b",
      () => api.unshareAgent("minimal", "group", "g_6f5b"),
    ],
    [
      // An address in a path segment. `@` and `.` are legal there and the encoder leaves
      // them alone; what it must not do is let a `/` in an address change the resource.
      "shareAgent by email",
      "/api/agents/minimal/grants/email/sam%40acme.com",
      () => api.shareAgent("minimal", "email", "sam@acme.com", "user"),
    ],
    // 12b. `/admin` is also a route this app owns, so the prefix matters here for
    // exactly the reason it mattered for `/agents` — a reload on it must reach the app.
    ["me", "/api/me", () => api.me()],
    ["adminAudit", "/api/admin-audit?limit=200", () => api.adminAudit()],
    ["adminAudit with a limit", "/api/admin-audit?limit=5", () => api.adminAudit(5)],
    // 035a. The door's traffic — the same capped-limit shape as the log above, because
    // it is the same kind of thing: a reader over an append-only table with no upper
    // bound on its size.
    ["adminDoorCalls", "/api/admin/door-calls?limit=200", () => api.adminDoorCalls()],
    [
      "adminDoorCalls with a limit",
      "/api/admin/door-calls?limit=5",
      () => api.adminDoorCalls({ limit: 5 }),
    ],
    // 066. The filters the Overview links with. An options object rather than
    // positionals, `adminDenials`' shape, because a fourth positional `undefined` at a
    // call site is how a filter ends up in the wrong slot.
    [
      "adminDoorCalls with a day and a decision",
      "/api/admin/door-calls?limit=200&since=2026-08-31&until=2026-08-31&decision=deny",
      () =>
        api.adminDoorCalls({
          since: "2026-08-31",
          until: "2026-08-31",
          decision: "deny",
        }),
    ],
    // `outcome=""` is a real stored value — the column is `NOT NULL DEFAULT ''` — so
    // asking for it must survive the client, where every other blank is dropped.
    [
      "adminDoorCalls asking for the calls nothing was recorded for",
      "/api/admin/door-calls?limit=200&outcome=",
      () => api.adminDoorCalls({ outcome: "" }),
    ],
    ["listGroups", "/api/groups", () => api.listGroups()],
  ] as [string, string, () => Promise<unknown>][])(
    "%s requests %s",
    async (_name, expected, call) => {
      const calls = stubFetch([]);
      await call();
      expect(calls[0].url).toBe(expected);
    },
  );

  it("sends JSON with its content type on every body", async () => {
    const calls = stubFetch({ name: "minimal", owner: "user:u_1" });
    await api.createAgent({ name: "minimal" });

    expect((calls[0].init.headers as Record<string, string>)["Content-Type"]).toBe(
      "application/json",
    );
  });

  it("sends the ETag back as a quoted If-Match, and nothing else", async () => {
    // **The header this whole step turns on.** The server answers 428 without it, and a
    // value that is not the one it handed out matches no row — so this is an echo and
    // never a construction. Quoted, because an ETag is a quoted-string by RFC 9110.
    const calls = stubFetch({});
    await api.updateAgent("minimal", { system: "x" }, "2026-08-08T04:12:33.482391+00:00");

    expect(calls[0].url).toBe("/api/agents/minimal");
    expect(calls[0].init.method).toBe("PATCH");
    expect((calls[0].init.headers as Record<string, string>)["If-Match"]).toBe(
      '"2026-08-08T04:12:33.482391+00:00"',
    );
  });

  it("renames through a POST that carries no precondition at all", async () => {
    // **The one write on an agent with no `If-Match`**, and the one directly above it in
    // `api.ts` has one — so this asserts the absence rather than trusting it. An edit form
    // races another edit form and needs a precondition; a rename is one deliberate act
    // from an owner, serialized on the row, and the loser gets the 404 that is true.
    const calls = stubFetch({});
    await api.renameAgent("minimal", "support-triage");

    expect(calls[0].url).toBe("/api/agents/minimal/rename");
    expect(calls[0].init.method).toBe("POST");
    expect(calls[0].init.headers as Record<string, string>).not.toHaveProperty("If-Match");
    expect(calls[0].init.body).toBe(JSON.stringify({ new_name: "support-triage" }));
  });

  it("escapes the old name in a rename, not just in a read", async () => {
    const calls = stubFetch({});
    await api.renameAgent("a/b", "c");
    expect(calls[0].url).toBe("/api/agents/a%2Fb/rename");
  });

  it("escapes a name rather than letting it change the path", async () => {
    // An agent named `a/b` must not become a request for a different resource.
    const calls = stubFetch({});
    await api.getAgent("a/b");
    expect(calls[0].url).toBe("/api/agents/a%2Fb");
  });

  it("restores through a POST with the same precondition a PATCH needs", async () => {
    // **Not `updateAgent` with an old config**, and the difference is silent: a merge
    // keeps every key the old config does not have, so a patch-composed restore produces
    // neither version while reporting success. Hence a route — and it carries `If-Match`
    // for the same reason the edit does, because it is the widest write in the product.
    const calls = stubFetch({});
    await api.restoreAgentVersion("minimal", 3, "2026-08-08T04:12:33.482391+00:00");

    expect(calls[0].url).toBe("/api/agents/minimal/versions/3/restore");
    expect(calls[0].init.method).toBe("POST");
    expect((calls[0].init.headers as Record<string, string>)["If-Match"]).toBe(
      '"2026-08-08T04:12:33.482391+00:00"',
    );
    // No body: the version in the URL is the whole request.
    expect(calls[0].init.body).toBeUndefined();
  });

  it("reads history without asking for the configs", async () => {
    const calls = stubFetch([]);
    await api.agentVersions("minimal");
    expect(calls[0].url).toBe("/api/agents/minimal/versions");
  });
});

describe("the token", () => {
  it("is attached to every request", async () => {
    const calls = stubFetch([]);
    await api.listTools();
    expect((calls[0].init.headers as Record<string, string>).Authorization).toBe(
      "Bearer a-token",
    );
  });

  it("is required — nothing is sent without one", async () => {
    vi.mocked(bearer).mockResolvedValue(null);
    const calls = stubFetch([]);

    await expect(api.listTools()).rejects.toBeInstanceOf(NotSignedIn);
    expect(calls).toHaveLength(0);
  });
});

describe("the 401 rule", () => {
  // `api/deps.py` goes out of its way to answer a distinct sentence for an expired
  // token, and says why: a client can act on it. This is the client that acts on it,
  // and the two halves must not be collapsed — renewing on a forged token loops.
  it("renews and retries exactly once on 'token expired'", async () => {
    const calls: string[] = [];
    let attempt = 0;
    vi.mocked(renew).mockResolvedValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        calls.push(url);
        attempt += 1;
        return attempt === 1
          ? ({ ok: false, status: 401, json: async () => ({ detail: "token expired" }) } as unknown as Response)
          : ({ ok: true, status: 200, json: async () => [] } as unknown as Response);
      }),
    );

    await api.listTools();

    expect(renew).toHaveBeenCalledTimes(1);
    expect(calls).toEqual(["/api/tools", "/api/tools"]);
  });

  it("signs out on any other 401 rather than looping on a renewal that cannot help", async () => {
    stubFetch({ detail: "not a valid token for this service" }, { status: 401 });

    await expect(api.listTools()).rejects.toBeInstanceOf(NotSignedIn);
    expect(renew).not.toHaveBeenCalled();
    expect(signOut).toHaveBeenCalledWith("not a valid token for this service");
  });

  it("does not sign out on a 403 — authenticating again would not help", async () => {
    stubFetch({ detail: "your domain is not registered" }, { status: 403 });

    await expect(api.listTools()).rejects.toBeInstanceOf(ApiError);
    expect(signOut).not.toHaveBeenCalled();
  });

  it("keeps a 409's structured fields, because prose is not something to branch on", async () => {
    stubFetch({ detail: "that name is taken", name: "minimal", owner: "user:u_2" }, { status: 409 });

    await api.createAgent({ name: "minimal" }).then(
      () => expect.fail("expected a rejection"),
      (error: unknown) => {
        expect(error).toBeInstanceOf(ApiError);
        expect((error as ApiError).status).toBe(409);
        expect((error as ApiError).extra).toEqual({ name: "minimal", owner: "user:u_2" });
      },
    );
  });

  it("never shows FastAPI's validation array to a person", async () => {
    // `detail` as a list of objects: "loc: body.task" teaches a reader nothing.
    stubFetch({ detail: [{ loc: ["body", "task"], msg: "field required" }] }, { status: 422 });

    await api.listTools().then(
      () => expect.fail("expected a rejection"),
      (error: unknown) => {
        expect((error as ApiError).detail).toBe(
          "the request was not in a shape the server accepts",
        );
      },
    );
  });
});

describe("connections (7b)", () => {
  it("asks for its own connections, with no principal anywhere in the URL", async () => {
    // There is no `?user=` and there will not be one until there is a tenant-admin role.
    // A route that could report somebody else's connections is an administrative route.
    const calls = stubFetch([]);

    await api.listConnections();

    expect(calls[0].url).toBe("/api/connections");
  });

  it("sends where the browser should come back to", async () => {
    const calls = stubFetch({ authorize_url: "https://auth.example.com/authorize" });

    await api.startConnect("jira", "/agents/triage-bot");

    expect(calls[0].url).toBe(
      "/api/connectors/jira/connect?return_to=%2Fagents%2Ftriage-bot",
    );
    expect(calls[0].init.method).toBe("POST");
  });

  it("returns a URL to navigate to rather than following it", async () => {
    // The client must do a **top-level navigation**. `fetch` follows a redirect
    // transparently and would land the provider's consent HTML in a promise.
    stubFetch({ authorize_url: "https://auth.example.com/authorize?state=xyz" });

    const started = await api.startConnect("jira", "/connections");

    expect(started.authorize_url).toBe("https://auth.example.com/authorize?state=xyz");
  });

  it("escapes a connector id rather than pasting it into a path", async () => {
    const calls = stubFetch({ disconnected: true, revoked_upstream: null });

    await api.disconnect("weird/id");

    expect(calls[0].url).toBe("/api/connectors/weird%2Fid/connection");
  });

  it("keeps disconnect's three-valued answer instead of coercing it", async () => {
    // `null` is "there was nobody to tell" and `false` is "we tried and could not".
    // Collapsing them to a boolean would make a provider outage look like a pasted
    // credential, which is the one distinction this response exists for.
    stubFetch({ disconnected: true, revoked_upstream: null });

    expect(await api.disconnect("jira")).toEqual({
      disconnected: true,
      revoked_upstream: null,
    });
  });

  it("surfaces a 400 from a connector with no consent flow", async () => {
    stubFetch(
      { detail: "connector 'jira' has no consent flow configured" },
      { status: 400 },
    );

    await api.startConnect("jira", "/connections").then(
      () => expect.fail("expected a rejection"),
      (error: unknown) => {
        expect((error as ApiError).status).toBe(400);
        expect((error as ApiError).detail).toMatch(/no consent flow/);
      },
    );
  });
});
