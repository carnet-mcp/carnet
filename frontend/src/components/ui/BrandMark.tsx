/** The vendor marks, as paths — `Icon.tsx`'s argument, applied to logos.
 *
 * **Drawn here rather than fetched.** A logo pulled from a vendor's CDN, or from one of
 * the favicon services that exist for exactly this, would tell an outside party which
 * vendors a customer has connected — on every render of an administration page — and would
 * need the CSP widened to let it. A path costs nothing and leaks nothing.
 *
 * **Where a mark cannot be drawn faithfully there is no mark.** An unrecognisable
 * near-miss of somebody's trademark is worse than an honest monogram, so a brand without a
 * `paths` entry gets its initial on a tinted tile in its own colour — which is what most
 * connector directories fall back to anyway, and which is never *wrong*, only plain.
 *
 * Adding a vendor is one row in `BRANDS`. Nothing else in the app has to know.
 */

import type { CSSProperties } from "react";

/** A vendor: the substrings that name it, its colour, and its mark if it has one. */
type Brand = {
  /** Matched as substrings against a connector id, a recipe id and a hostname, in that
   *  order. First match wins, so put the specific before the general. */
  match: string[];
  label: string;
  /** The tile's ink. The tile itself is this colour at low alpha — one value rather than
   *  two, so a new row cannot get the pair subtly out of step. */
  color: string;
  /** A 24×24 mark. `stroke` draws it with the tile's ink and no fill; the default is a
   *  filled path. Absent means the monogram. */
  paths?: string[];
  stroke?: boolean;
  /** Overrides the initial the monogram would take. Only used when `paths` is absent. */
  initial?: string;
};

const BRANDS: Brand[] = [
  {
    // The real mark. It is the one logo here common enough that an approximation would
    // be recognised as an approximation.
    match: ["github"],
    label: "GitHub",
    color: "#1f2328",
    paths: [
      "M12 .3a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2c-3.3.7-4-1.6-4-1.6-.6-1.4-1.4-1.8-1.4-1.8-1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1.1 1.9 2.8 1.3 3.5 1 .1-.8.4-1.3.8-1.6-2.7-.3-5.5-1.3-5.5-6 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.5.1-3.2 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0C17.2 4.9 18.2 5.2 18.2 5.2c.6 1.7.2 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.6-2.8 5.6-5.5 5.9.4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0 0 12 .3",
    ],
  },
  {
    // Jira's mark is a chevron sitting inside a larger chevron of the same angle. Drawn,
    // not traced: at 24px what carries the recognition is the shape and Atlassian blue.
    match: ["jira", "atlassian", "confluence"],
    label: "Jira",
    color: "#1868db",
    paths: [
      "M12 1.5 22.5 12 18.9 15.6 12 8.7 5.1 15.6 1.5 12z",
      "M12 11.4 17.4 16.8 12 22.2 6.6 16.8z",
    ],
  },
  {
    // A rounded square ruled corner to corner — Linear's shape, in Linear's indigo.
    // **Two diagonals, not four.** The mark itself has more; at 22px on a tile they
    // merged into a smudge, which is the failure the monogram exists to avoid and is no
    // better for being a drawing.
    match: ["linear"],
    label: "Linear",
    color: "#5e6ad2",
    stroke: true,
    paths: [
      "M7 3h10a4 4 0 0 1 4 4v10a4 4 0 0 1-4 4H7a4 4 0 0 1-4-4V7a4 4 0 0 1 4-4z",
      "m3.6 9.5 10.9 10.9",
      "m5 4.6 14.4 14.4",
    ],
  },
  {
    // Notion's logo is an N in a ruled square, which is a thing that can be drawn exactly.
    match: ["notion"],
    label: "Notion",
    color: "#191918",
    stroke: true,
    paths: [
      "M4.5 3.5h15a1 1 0 0 1 1 1v15a1 1 0 0 1-1 1h-15a1 1 0 0 1-1-1v-15a1 1 0 0 1 1-1z",
      "M9 16.5v-9l6 9v-9",
    ],
  },
  {
    // The A, as a chevron with its bar — Anthropic's letterform, in Anthropic's clay.
    match: ["anthropic", "claude"],
    label: "Anthropic",
    color: "#d97757",
    stroke: true,
    paths: ["M4 20 12 4l8 16", "M7.6 13.5h8.8"],
  },
  {
    // No mark. OpenAI's is an interlocking hexagonal knot and there is no version of it
    // that survives being drawn from memory — an honest O is better than a bad knot.
    match: ["openai", "chatgpt", "gpt"],
    label: "OpenAI",
    color: "#0f8a72",
    initial: "O",
  },
  { match: ["gitlab"], label: "GitLab", color: "#e24329" },
  { match: ["slack"], label: "Slack", color: "#611f69" },
  { match: ["google", "gmail", "gcal", "gdrive"], label: "Google", color: "#1a73e8" },
  { match: ["microsoft", "azure", "outlook", "sharepoint"], label: "Microsoft", color: "#0067b8" },
  { match: ["salesforce"], label: "Salesforce", color: "#0d9dda" },
  { match: ["hubspot"], label: "HubSpot", color: "#ff5c35" },
  { match: ["zendesk"], label: "Zendesk", color: "#03363d" },
  { match: ["stripe"], label: "Stripe", color: "#635bff" },
  { match: ["asana"], label: "Asana", color: "#f06a6a" },
  { match: ["figma"], label: "Figma", color: "#a259ff" },
  { match: ["sentry"], label: "Sentry", color: "#6a5fc1" },
  { match: ["datadog"], label: "Datadog", color: "#632ca6" },
  { match: ["pagerduty"], label: "PagerDuty", color: "#06ac38" },
  { match: ["snowflake"], label: "Snowflake", color: "#29b5e8" },
  { match: ["databricks"], label: "Databricks", color: "#ff3621" },
  { match: ["dataiku"], label: "Dataiku", color: "#2ab1ac" },
  { match: ["servicenow"], label: "ServiceNow", color: "#0f7d5c" },
  { match: ["okta"], label: "Okta", color: "#0f6ab4" },
  { match: ["workday"], label: "Workday", color: "#f38b00" },
  { match: ["shopify"], label: "Shopify", color: "#5e8e3e" },
  { match: ["intercom"], label: "Intercom", color: "#1f8ded" },
  { match: ["airtable"], label: "Airtable", color: "#f82b60" },
  { match: ["dropbox", "box.com"], label: "Dropbox", color: "#0061ff" },
  { match: ["twilio"], label: "Twilio", color: "#f22f46" },
  { match: ["mongodb", "atlas"], label: "MongoDB", color: "#00684a" },
  { match: ["postgres"], label: "Postgres", color: "#336791" },
  { match: ["elastic"], label: "Elastic", color: "#0077cc" },
  { match: ["cloudflare"], label: "Cloudflare", color: "#f6821f" },
];

/** The six hues an unrecognised connector's monogram may take.
 *
 *  Deliberately not the status palette and deliberately not `--chart-*`: this colour means
 *  nothing at all, it is only there so that eight unrecognised connectors are eight
 *  different tiles rather than a column of identical grey squares. Picked by a hash of the
 *  id, so a connector keeps its colour across renders, reloads and machines. */
const HUES = ["#4f46e5", "#0f766e", "#b45309", "#9333ea", "#0369a1", "#be123c"];

function hue(seed: string): string {
  let total = 0;
  for (let i = 0; i < seed.length; i += 1) total = (total * 31 + seed.charCodeAt(i)) % 100003;
  return HUES[total % HUES.length];
}

/** The brand a string names, or null. Exported for the tests, which is the only way to
 *  assert that `internal-github-proxy` is GitHub without going through a rendered tile. */
export function brandOf(...hints: (string | null | undefined)[]): Brand | null {
  const hay = hints.filter(Boolean).join(" ").toLowerCase();
  if (!hay) return null;
  for (const brand of BRANDS) {
    if (brand.match.some((needle) => hay.includes(needle))) return brand;
  }
  return null;
}

/** A vendor's mark, or its initial, on a tinted tile.
 *
 *  `aria-hidden` for `Icon`'s reason: every one of these sits beside the name it stands
 *  for, and a tile that announced itself would make a screen reader say "GitHub" twice.
 *  The name beside it is what gets read out.
 */
export function BrandMark({
  /** Everything that might name the vendor — a connector id, a recipe id, a hostname.
   *  Matched in the order given. */
  hints,
  size = 40,
  /** No vendor at all: a neutral tile with a plus in it. The "something else" card is
   *  not an unrecognised vendor with an unlucky initial, it is the absence of one — and a
   *  monogram there invents a brand called C. */
  plain = false,
}: {
  hints: (string | null | undefined)[];
  size?: number;
  plain?: boolean;
}) {
  if (plain) {
    return (
      <span
        className="brandmark plain"
        aria-hidden="true"
        style={{ width: `${size}px`, height: `${size}px` }}
      >
        <svg
          viewBox="0 0 24 24"
          width={size * 0.5}
          height={size * 0.5}
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          strokeLinecap="round"
          focusable="false"
        >
          <path d="M12 5v14" />
          <path d="M5 12h14" />
        </svg>
      </span>
    );
  }

  const brand = brandOf(...hints);
  const seed = hints.find(Boolean) ?? "";
  const color = brand?.color ?? hue(String(seed));
  const letter = (brand?.initial ?? String(seed).replace(/[^a-z0-9]/gi, "")[0] ?? "?").toUpperCase();

  return (
    <span
      className="brandmark"
      aria-hidden="true"
      style={{
        // The tile is the ink at low alpha rather than a second checked-in value, so a
        // new row in BRANDS cannot get the pair out of step. `color-mix` degrades to the
        // declared fallback nowhere we ship — every browser in the support matrix has it.
        "--brand": color,
        width: `${size}px`,
        height: `${size}px`,
      } as CSSProperties}
    >
      {brand?.paths ? (
        <svg
          viewBox="0 0 24 24"
          width={size * 0.55}
          height={size * 0.55}
          fill={brand.stroke ? "none" : "currentColor"}
          stroke={brand.stroke ? "currentColor" : "none"}
          strokeWidth={brand.stroke ? 2.1 : undefined}
          strokeLinecap="round"
          strokeLinejoin="round"
          focusable="false"
        >
          {brand.paths.map((d) => (
            <path key={d} d={d} />
          ))}
        </svg>
      ) : (
        <span className="brandmark-letter" style={{ fontSize: `${size * 0.42}px` }}>
          {letter}
        </span>
      )}
    </span>
  );
}
