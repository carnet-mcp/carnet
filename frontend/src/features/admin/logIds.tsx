/** An id in a log cell, as the thing it names. 110f, plan 107 D10.
 *
 *  Three logs printed ids as mono text, and a reader who wanted the agent a grant was
 *  about copied the name into the address bar. Where a page exists for the kind — an
 *  agent, a token, a connector, the groups page — the id is a link to it; where none
 *  does, and the log has a filter for the column, it is the filter button `DenialsPage`
 *  already had; otherwise it is the text it was. One table for the three pages, so the
 *  denials and request logs agree about which ids go somewhere.
 *
 *  A link to an agent that has since been removed is a link to a 404 page, and that is
 *  the truthful outcome: the log says what happened to a thing, and the page says the
 *  thing is gone. The alternative — a request per row to check — is the directory
 *  rebuilt to render a log.
 */

import { Link } from "react-router-dom";

/** Where a kind's page is, or null when there is none. The kinds are the server's
 *  vocabularies — `ADMIN_TARGET_KINDS`, `DENIAL_RESOURCE_KINDS`, the door's
 *  `principal_kind` — and a kind absent here renders as text, so a new one on the
 *  server is a missing shortcut rather than a broken cell. */
export function pageFor(kind: string, id: string): string | null {
  if (!id) return null;
  switch (kind) {
    case "agent":
      return `/agents/${encodeURIComponent(id)}`;
    case "machine":
    case "token":
      return `/tokens/${encodeURIComponent(id)}`;
    case "connector":
      return `/admin/connectors/${encodeURIComponent(id)}`;
    case "group":
      return "/admin/groups";
    default:
      return null;
  }
}

/** The id, as a link where a page exists, else as a filter button where `onPick` is
 *  given, else as text. */
export function LogId({
  kind,
  id,
  onPick,
  title,
}: {
  kind: string;
  id: string;
  onPick?: (value: string) => void;
  title?: string;
}) {
  const page = pageFor(kind, id);
  if (page) {
    return (
      <Link to={page} className="mono">
        {id}
      </Link>
    );
  }
  if (onPick) {
    return (
      <button type="button" className="filter-value" title={title} onClick={() => onPick(id)}>
        {id}
      </button>
    );
  }
  return <span className="mono">{id}</span>;
}
