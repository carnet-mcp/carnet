/** The client dialects the connect card can speak. Step 075.
 *
 *  The door's payload is a URL and one header, and every MCP client that can hold a
 *  remote server holds exactly those two things — in its own file, in its own shape.
 *  This is the table of those shapes. It is a catalogue and deliberately not an
 *  installer: nothing here is written to anybody's machine, and the reasons are in
 *  `DEFERRED_2.0.md`'s refused list (an installer re-creates fifty-tokens-on-fifty-
 *  laptops in a new currency).
 *
 *  ## Two properties every entry keeps
 *
 *  - **The snippet says `<your token>`.** This page never sees a secret and must not
 *    invite pasting one into it; the card's own docstring settled that in 044.
 *  - **A client that cannot reach *this* origin gets the reason, not a snippet.** A
 *    client that refuses `http://` cannot connect to a deployment whose door is not
 *    behind TLS. `unreachable()` says so, and the card renders that sentence in place of
 *    a config that would not have worked. (Until step 083 there was a second reason —
 *    a client that only speaks OAuth — and the door now speaks it.)
 *  - **An `oauth` dialect's snippet is the URL alone.** No header, no token: the client
 *    discovers the door's OAuth documents and sends the person to the consent page.
 *
 *  ## Verified, or from the vendor's documentation
 *
 *  `verified` is **true only for a dialect tried against the real client**, and the
 *  card renders the *where to paste it* sentence only for those. The register's rule:
 *  a wrong path on that card is worse than no card. Evo's path catalogue was verified
 *  for writing *plugin* entries, not MCP server entries, and Claude Code is the case in
 *  point — its plugin directory is `~/.claude/` and its MCP servers are in
 *  `~/.claude.json` (user scope) or `.mcp.json` (project scope), which `claude mcp add`
 *  writes. Promoting an entry is one boolean, flipped after somebody has pasted the
 *  snippet into the real client and watched `tools/list` arrive; the plan for 071
 *  records which were tried and how.
 *
 *  ## Frameworks are the same table with a different heading (step 111)
 *
 *  LangChain, CrewAI, the OpenAI Agents SDK and AutoGen each ship an MCP adapter that
 *  speaks Streamable HTTP with a bearer header — which is exactly what `/mcp` is. A
 *  developer could wire any of them to a door before this table said so; the gap was
 *  that the four lines proving it were written down nowhere. So they are entries here,
 *  under `group: "framework"`, and they inherit the rule above rather than restating
 *  it: a snippet is `verified` only once it has been run against the real library and
 *  a real door, and the card says so for the ones that have not. `where` for a
 *  framework is where in the *code* it goes, since there is no file to paste into.
 *  Each was run from here against a fileborne door — LangChain on 2026-09-19
 *  (`langchain-mcp-adapters` 0.3.2), the OpenAI Agents SDK (`openai-agents` 0.22.3),
 *  AutoGen (`autogen-ext` 0.7.5, with `mcp<2`) and CrewAI (`crewai-tools` 1.15.22 with
 *  its `[mcp]` extra) on 2026-09-20: `tools/list` arrived, an in-scope call ran under
 *  the broker's credential, and an out-of-scope call came back as the broker's refusal.
 *  Two of the four had a snag worth a sentence in `where`: AutoGen's MCP extra pulls
 *  an `mcp` it cannot import, and CrewAI's adapter needs `crewai-tools[mcp]` or it
 *  stops at an interactive prompt asking to install it. Plan 111's addendum has the
 *  procedure.
 */

export type Dialect = {
  id: string;
  label: string;
  /** A client is a program somebody configures — a file, a command, a settings pane.
   *  A framework is a library somebody imports, and its snippet is code. The card
   *  renders the two groups apart, and the caveat for an unverified entry differs:
   *  a client's is about the file location, a framework's about the library's API. */
  group: "client" | "framework";
  /** How the client authenticates to a remote server. `header` is a pasted token;
   *  `oauth` is a client that discovers the door's OAuth documents and sends the person
   *  here to sign in and approve — offered since step 083. */
  auth: "header" | "oauth";
  /** Whether the client refuses a plain `http://` address for a remote server. Only
   *  `true` where the vendor documents the refusal; a guess here would turn a working
   *  local deployment into a reason. */
  needsHttps: boolean;
  /** Tried against the real client, so the `where` sentence may be shown. */
  verified: boolean;
  /** Where the client reads it, in words — shown only when `verified`. */
  where: string;
  /** The config, with the door's URL substituted. Empty for a client that gets a
   *  reason instead (see `unreachable`). */
  snippet: (url: string) => string;
};

const HEADER = { Authorization: "Bearer <your token>" };

function json(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export const DIALECTS: Dialect[] = [
  {
    id: "claude-code",
    label: "Claude Code",
    group: "client",
    auth: "header",
    needsHttps: false,
    verified: true,
    where:
      "Run the command in a terminal; Claude Code writes the entry itself. `-s user` keeps it in ~/.claude.json for every project, `-s project` writes .mcp.json in the repository so a team shares it.",
    snippet: (url) =>
      `claude mcp add --transport http carnet ${url} \\\n  --header "Authorization: Bearer <your token>"\n\n# or, as the .mcp.json entry the command writes:\n${json({
        mcpServers: { carnet: { type: "http", url, headers: HEADER } },
      })}`,
  },
  {
    id: "cursor",
    label: "Cursor",
    group: "client",
    auth: "header",
    needsHttps: false,
    verified: false,
    where: "~/.cursor/mcp.json for every project, or .cursor/mcp.json in one repository.",
    snippet: (url) => json({ mcpServers: { carnet: { url, headers: HEADER } } }),
  },
  {
    id: "vscode",
    label: "VS Code",
    group: "client",
    auth: "header",
    needsHttps: false,
    verified: false,
    where: ".vscode/mcp.json in the workspace, or the user-level mcp.json the MCP: Open User Configuration command opens.",
    snippet: (url) => json({ servers: { carnet: { type: "http", url, headers: HEADER } } }),
  },
  {
    id: "codex",
    label: "Codex CLI",
    group: "client",
    auth: "header",
    needsHttps: false,
    verified: false,
    where: "$CODEX_HOME/config.toml, which is ~/.codex/config.toml unless CODEX_HOME is set.",
    snippet: (url) =>
      `[mcp_servers.carnet]\nurl = "${url}"\nhttp_headers = { Authorization = "Bearer <your token>" }`,
  },
  {
    id: "opencode",
    label: "opencode",
    group: "client",
    auth: "header",
    needsHttps: false,
    verified: false,
    where: "$XDG_CONFIG_HOME/opencode/opencode.json, which is ~/.config/opencode/opencode.json unless XDG_CONFIG_HOME is set; or opencode.json in the project.",
    snippet: (url) => json({ mcp: { carnet: { type: "remote", url, headers: HEADER } } }),
  },
  {
    id: "gemini-cli",
    label: "Gemini CLI",
    group: "client",
    auth: "header",
    needsHttps: false,
    verified: false,
    where: "~/.gemini/settings.json, or .gemini/settings.json in the project.",
    snippet: (url) => json({ mcpServers: { carnet: { httpUrl: url, headers: HEADER } } }),
  },
  {
    id: "windsurf",
    label: "Windsurf",
    group: "client",
    auth: "header",
    needsHttps: false,
    verified: false,
    where: "~/.codeium/windsurf/mcp_config.json.",
    snippet: (url) => json({ mcpServers: { carnet: { serverUrl: url, headers: HEADER } } }),
  },
  {
    id: "claude-ai",
    label: "Claude.ai and Claude Desktop",
    group: "client",
    auth: "oauth",
    needsHttps: true,
    verified: false,
    where: "Claude.ai: Settings → Connectors → Add custom connector. Claude Desktop: Settings → Connectors. Paste the URL; you will be sent here to sign in and approve.",
    // No header and no token: the client discovers the door's OAuth documents, sends the
    // person here to consent (step 083), and holds a token it minted for itself.
    snippet: (url) => url,
  },
  // --- frameworks (step 111). Code, not config; `<your token>` is still the rule. ---
  {
    id: "langchain",
    label: "LangChain",
    group: "framework",
    auth: "header",
    needsHttps: false,
    verified: true,
    where:
      "pip install langchain-mcp-adapters. Build the client wherever your agent assembles its tools and pass what get_tools() returns to create_agent or your graph. A call outside the token's scope comes back as the broker's refusal in the tool result, for the model to read.",
    snippet: (url) =>
      `from langchain_mcp_adapters.client import MultiServerMCPClient\n\n` +
      `client = MultiServerMCPClient({\n` +
      `    "carnet": {\n` +
      `        "transport": "streamable_http",\n` +
      `        "url": "${url}",\n` +
      `        "headers": {"Authorization": "Bearer <your token>"},\n` +
      `    }\n` +
      `})\n` +
      `tools = await client.get_tools()  # hand these to create_agent or your graph`,
  },
  {
    id: "crewai",
    label: "CrewAI",
    group: "framework",
    auth: "header",
    needsHttps: false,
    verified: true,
    where:
      "pip install \"crewai-tools[mcp]\" — without the extra the adapter stops at an interactive prompt asking to install it. Use the adapter as a context manager and pass its tools to an Agent. A call outside the token's scope comes back as the broker's sentence in the tool's result, for the model to read.",
    snippet: (url) =>
      `from crewai_tools import MCPServerAdapter\n\n` +
      `with MCPServerAdapter({\n` +
      `    "url": "${url}",\n` +
      `    "transport": "streamable-http",\n` +
      `    "headers": {"Authorization": "Bearer <your token>"},\n` +
      `}) as tools:\n` +
      `    ...  # Agent(role=..., goal=..., tools=tools)`,
  },
  {
    id: "openai-agents",
    label: "OpenAI Agents SDK",
    group: "framework",
    auth: "header",
    needsHttps: false,
    verified: true,
    where:
      "pip install openai-agents. Open the server as a context manager and name it in the Agent's mcp_servers. A call outside the token's scope comes back as a tool result with is_error set and the broker's sentence, for the model to read.",
    snippet: (url) =>
      `from agents import Agent\n` +
      `from agents.mcp import MCPServerStreamableHttp\n\n` +
      `async with MCPServerStreamableHttp(\n` +
      `    name="carnet",\n` +
      `    params={"url": "${url}", "headers": {"Authorization": "Bearer <your token>"}},\n` +
      `) as server:\n` +
      `    agent = Agent(name="triage", instructions="...", mcp_servers=[server])`,
  },
  {
    id: "autogen",
    label: "AutoGen",
    group: "framework",
    auth: "header",
    needsHttps: false,
    verified: true,
    where:
      "pip install \"autogen-ext[mcp]\" \"mcp<2\" — autogen-ext 0.7 does not import against mcp 2.x. Pass what mcp_server_tools() returns to an AssistantAgent. Note that AutoGen's own adapter raises on a call outside the token's scope rather than handing the model the sentence; the carnet-mcp package's adapter returns it.",
    snippet: (url) =>
      `from autogen_ext.tools.mcp import StreamableHttpServerParams, mcp_server_tools\n\n` +
      `params = StreamableHttpServerParams(\n` +
      `    url="${url}",\n` +
      `    headers={"Authorization": "Bearer <your token>"},\n` +
      `)\n` +
      `tools = await mcp_server_tools(params)  # AssistantAgent(..., tools=tools)`,
  },
];

export const DEFAULT_DIALECT = DIALECTS[0].id;

export function dialect(id: string): Dialect {
  return DIALECTS.find((entry) => entry.id === id) ?? DIALECTS[0];
}

/** Why this client cannot connect to this door, or null when it can.
 *
 *  One reason since step 083, and it is about the deployment rather than the client: a
 *  client that refuses `http://` cannot reach a door that is not behind TLS. The other
 *  reason — *this door offers no OAuth sign-in* — was true from 044 to 082 and is not
 *  any more: the door serves the two `.well-known` documents, registers clients and
 *  mints a token at the end of a consent, so a client that only speaks OAuth connects
 *  with the URL alone. */
export function unreachable(entry: Dialect, url: string): string | null {
  if (entry.needsHttps && url.startsWith("http://")) {
    return (
      `${entry.label} requires an https:// address for a remote server. This ` +
      `deployment's MCP server URL is ${url}. Put it behind TLS to connect from ` +
      `${entry.label}.`
    );
  }
  return null;
}

/** The order the connect card shows clients in (plan 107 D9). Claude — claude.ai and
 *  Claude Desktop — first on an https deployment, because it is where most people
 *  start and it needs nothing pasted; on plain http it stays first only in the reason
 *  it gives, so it moves under *More* rather than leading with a sentence about TLS.
 *  Then Claude Code, Cursor and VS Code; everything else under *More*. */
export function ordered(url: string): { primary: Dialect[]; more: Dialect[] } {
  const https = url.startsWith("https://");
  const lead = https ? ["claude-ai", "claude-code", "cursor", "vscode"] : ["claude-code", "cursor", "vscode"];
  const primary = lead.map(dialect);
  const more = DIALECTS.filter((entry) => entry.group === "client" && !lead.includes(entry.id));
  return { primary, more };
}

/** The framework group (step 111), in table order — LangChain first because it is the
 *  one that has been run from here. Rendered as its own tab beside the clients rather
 *  than under *More*, because a person wiring a library is not looking for a file. */
export function frameworks(): Dialect[] {
  return DIALECTS.filter((entry) => entry.group === "framework");
}

export function defaultDialect(url: string): string {
  return ordered(url).primary[0].id;
}
