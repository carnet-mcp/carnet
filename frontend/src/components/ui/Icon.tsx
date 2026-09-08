/** The icons, as paths.
 *
 * **Hand-written rather than a dependency**, for the same reason the primitives next door
 * are: this app needs a couple of dozen glyphs for one sidebar, a handful of buttons and
 * the three tones a notice comes in, and an icon package is thousands of them plus a
 * build step to shake the rest back out. A path on a 24×24 grid is smaller than the
 * import line.
 *
 * They are drawn with `stroke="currentColor"`, so an icon is whatever colour its text is —
 * an active nav row tints its icon by tinting the row, and nothing here needs to know
 * about the palette.
 *
 * **Always `aria-hidden`.** Every icon in this app sits beside its own label, or inside a
 * control that carries an accessible name of its own. An icon that announced itself would
 * make a screen reader say "Agents" twice.
 */

export type IconName =
  | "agents"
  | "connections"
  | "tokens"
  | "overview"
  | "admin"
  | "door"
  | "denied"
  | "groups"
  | "connectors"
  | "signout"
  | "collapse"
  | "expand"
  | "plus"
  | "check"
  | "copy"
  | "info"
  | "warn"
  | "alert"
  | "inbox";

const PATHS: Record<IconName, string[]> = {
  agents: ["M12 3v3", "M5 6h14a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2z", "M9 12v2", "M15 12v2"],
  connections: [
    "M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7",
    "M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7",
  ],
  // 035c, and a glyph of its own rather than a reused one — which is the *opposite* call
  // from 035a and 035b, deliberately. Those reused `log` because three logs are three
  // labels and not three glyphs. A token is not another log, and it is not another
  // connection either: a connection is your account at somebody else's service, and this
  // is a credential into this one.
  tokens: [
    "M13 15.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0",
    "m21 2-9.6 9.6",
    "m15.5 7.5 3 3L22 7l-3-3",
  ],
  // Three columns rising. The overview is the only screen in the app that draws
  // anything, and the glyph says so before the word does — which matters most in a
  // collapsed rail, where the word is gone and this is the row somebody opens first.
  // Deliberately not a gauge or a pie: neither form appears on the page, and a rail
  // icon that promises a chart the screen does not contain is a small lie told daily.
  overview: [
    "M4 20h16",
    "M7 20v-6",
    "M12 20V8",
    "M17 20v-9",
  ],
  // **Three glyphs where there was one.** 035a and 035b each reused `log` on the
  // argument that three logs are three labels and not three glyphs — which is true of
  // the *word* and false of the row: a rail with Administration, Door traffic and
  // Access denials stacked under one identical list icon gives the eye nothing to aim
  // at, and the icon is what a person navigates by once they know the app. So each one
  // is now drawn as the thing it is rather than as the shape of a log.
  //
  // A shield and a tick: this log is *who changed who may do what*, which is the record
  // of authorization rather than of traffic.
  admin: [
    "M20 13c0 5-3.5 7.5-7.7 8.9a1 1 0 0 1-.6 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.2-2.7a1 1 0 0 1 1.6 0C14.5 3.8 17 5 19 5a1 1 0 0 1 1 1z",
    "m9 12 2 2 4-4",
  ],
  // A literal door, because the screen is literally the door's traffic — what came
  // through the MCP door, for whom, and whether it was allowed.
  door: [
    "M13 4.8v14.4a1 1 0 0 1-1.2 1l-6-1.2A1 1 0 0 1 5 18V6a1 1 0 0 1 .8-1l6-1.2A1 1 0 0 1 13 4.8z",
    "M13 4h3a2 2 0 0 1 2 2v14",
    "M3 20h18",
    "M10 12h.01",
  ],
  // The one sign that needs no label. A denial log is a list of refusals, and a circle
  // with a bar through it is what a refusal looks like everywhere else too.
  denied: [
    "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18",
    "m5.6 5.6 12.8 12.8",
  ],
  groups: [
    "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2",
    "M9 3a4 4 0 1 1 0 8 4 4 0 0 1 0-8z",
    "M22 21v-2a4 4 0 0 0-3-3.9",
    "M16 3.1a4 4 0 0 1 0 7.8",
  ],
  connectors: [
    "M3 4a1 1 0 0 1 1-1h5a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z",
    "M14 4a1 1 0 0 1 1-1h5a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1h-5a1 1 0 0 1-1-1z",
    "M3 15a1 1 0 0 1 1-1h5a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z",
    "M14 15a1 1 0 0 1 1-1h5a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1h-5a1 1 0 0 1-1-1z",
  ],
  signout: ["M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4", "m16 17 5-5-5-5", "M21 12H9"],
  collapse: ["m11 17-5-5 5-5", "m18 17-5-5 5-5"],
  expand: ["m13 17 5-5-5-5", "m6 17 5-5-5-5"],
  plus: ["M12 5v14", "M5 12h14"],
  check: ["m20 6-11 11-5-5"],
  copy: [
    "M9 11a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-9a2 2 0 0 1-2-2z",
    "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1",
  ],

  // The three tones a `Notice` comes in, and the glyph an `Empty` sits under. They are
  // each a **second** signal rather than a first: the notice already carries a colour
  // and a sentence, and the shape is what survives a reader who cannot tell the amber
  // border from the red one — a triangle is not a circle at any colour.
  info: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18", "M12 11v5", "M12 7.5h.01"],
  warn: [
    "M10.3 4.3 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0z",
    "M12 9.5v4",
    "M12 17.5h.01",
  ],
  alert: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18", "m14.5 9.5-5 5", "m9.5 9.5 5 5"],
  inbox: [
    "M22 12h-5.5l-1.6 2.4a1 1 0 0 1-.8.4h-4.2a1 1 0 0 1-.8-.4L7.5 12H2",
    "M5.6 5.2 2.2 11.6a2 2 0 0 0-.2.9V19a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6.5a2 2 0 0 0-.2-.9l-3.4-6.4A2 2 0 0 0 16.6 4H7.4a2 2 0 0 0-1.8 1.2z",
  ],
};

export function Icon({ name, size = 16 }: { name: IconName; size?: number }) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[name].map((d) => (
        <path key={d} d={d} />
      ))}
    </svg>
  );
}
