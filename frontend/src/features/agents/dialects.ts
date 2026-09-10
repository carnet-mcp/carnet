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
 */

export type Dialect = {
  id: string;
  label: string;
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
    auth: "header",
    needsHttps: false,
    verified: false,
    where: "~/.cursor/mcp.json for every project, or .cursor/mcp.json in one repository.",
    snippet: (url) => json({ mcpServers: { carnet: { url, headers: HEADER } } }),
  },
  {
    id: "vscode",
    label: "VS Code",
    auth: "header",
    needsHttps: false,
    verified: false,
    where: ".vscode/mcp.json in the workspace, or the user-level mcp.json the MCP: Open User Configuration command opens.",
    snippet: (url) => json({ servers: { carnet: { type: "http", url, headers: HEADER } } }),
  },
  {
    id: "codex",
    label: "Codex CLI",
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
    auth: "header",
    needsHttps: false,
    verified: false,
    where: "$XDG_CONFIG_HOME/opencode/opencode.json, which is ~/.config/opencode/opencode.json unless XDG_CONFIG_HOME is set; or opencode.json in the project.",
    snippet: (url) => json({ mcp: { carnet: { type: "remote", url, headers: HEADER } } }),
  },
  {
    id: "gemini-cli",
    label: "Gemini CLI",
    auth: "header",
    needsHttps: false,
    verified: false,
    where: "~/.gemini/settings.json, or .gemini/settings.json in the project.",
    snippet: (url) => json({ mcpServers: { carnet: { httpUrl: url, headers: HEADER } } }),
  },
  {
    id: "windsurf",
    label: "Windsurf",
    auth: "header",
    needsHttps: false,
    verified: false,
    where: "~/.codeium/windsurf/mcp_config.json.",
    snippet: (url) => json({ mcpServers: { carnet: { serverUrl: url, headers: HEADER } } }),
  },
  {
    id: "claude-ai",
    label: "Claude.ai and Claude Desktop",
    auth: "oauth",
    needsHttps: true,
    verified: false,
    where: "Claude.ai: Settings → Connectors → Add custom connector. Claude Desktop: Settings → Connectors. Paste the URL; you will be sent here to sign in and approve.",
    // No header and no token: the client discovers the door's OAuth documents, sends the
    // person here to consent (step 083), and holds a token it minted for itself.
    snippet: (url) => url,
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
