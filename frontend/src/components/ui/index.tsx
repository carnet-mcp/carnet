/** The ten primitives.
 *
 * One file, because each is between three and fifteen lines and a directory of
 * ten three-line files is a filing system rather than a design. The plan's scope cut
 * stands: no component library in 10a — its screens are a list, a form field, a table, a
 * status badge and a button, and a dependency that answers to a generic design would be
 * larger than this and less ours. Revisit at 10b, where a combobox and a dialog have
 * real behaviour worth not reimplementing.
 *
 * Nothing here knows what an agent or a run is. The moment one of them does, it belongs
 * in `features/`.
 */

import type { KeyboardEvent, ReactNode } from "react";
import { Link } from "react-router-dom";

import { Icon, type IconName } from "./Icon";

export { Icon } from "./Icon";
export type { IconName } from "./Icon";
export { BrandMark, brandOf } from "./BrandMark";

// --- Badge ---------------------------------------------------------------------------

/** A status, as a word and a colour — **never as a colour alone.** These colours mean
 *  "somebody's real systems were written to", and a reader who cannot distinguish two of
 *  them must not lose the distinction. */
/** The colour a status carries: waiting, in progress, good, warning, bad. */
export type Tone = "waiting" | "going" | "good" | "warn" | "bad";

export function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={`badge ${tone}`}>
      <span className="pip" aria-hidden="true" />
      {children}
    </span>
  );
}

// --- Button --------------------------------------------------------------------------

type Kind = "plain" | "primary" | "danger" | "quiet";

/** A button, or — with `to` — a link wearing the same clothes.
 *
 *  **The `to` form exists because five call sites had already invented it**, as
 *  `<Link className="btn primary">`. Going somewhere and doing something look identical
 *  in this design and are not the same element: a link has an href, so it opens in a new
 *  tab on a middle click and tells a screen reader it navigates. Hand-writing the class
 *  got the appearance and quietly lost the rest, and there was nothing stopping the sixth
 *  call site from spelling the class slightly differently.
 *
 *  The two forms do not mix: `to` takes no `onClick`, `busy` or `disabled`, because a
 *  disabled link is not a thing HTML has and a busy one has already left the page. */
type ButtonProps =
  | {
      to: string;
      kind?: Kind;
      children: ReactNode;
      busy?: never;
      disabled?: never;
      onClick?: never;
      type?: never;
    }
  | {
      to?: undefined;
      kind?: Kind;
      children: ReactNode;
      busy?: boolean;
      disabled?: boolean;
      onClick?: () => void;
      type?: "button" | "submit";
    };

export function Button(props: ButtonProps) {
  const { kind = "plain", children } = props;
  const className = `btn ${kind === "plain" ? "" : kind}`;

  if (props.to !== undefined) {
    return (
      <Link to={props.to} className={className}>
        {children}
      </Link>
    );
  }

  const { busy = false, disabled, onClick, type = "button" } = props;
  return (
    <button
      type={type}
      className={className}
      disabled={disabled || busy}
      onClick={onClick}
    >
      {busy && <Spinner />}
      {children}
    </button>
  );
}

// --- Card ----------------------------------------------------------------------------

export function Card({
  title,
  hint,
  children,
}: {
  title?: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <section className="card">
      {title && (
        <div className="card-title">
          <h2>{title}</h2>
          {hint && <span className="hint">{hint}</span>}
        </div>
      )}
      {children}
    </section>
  );
}

// --- PageHead ------------------------------------------------------------------------

/** A page's title, its sentence, and the things you can do to it.
 *
 *  `actions` is here rather than left to each page because it was already on every page,
 *  spelled a slightly different way each time — a flex row with an inline margin at one
 *  call site, a bare `<Link className="btn">` at the next. One place, so "New agent" and
 *  "Edit" sit in the same spot on every screen. */
export function PageHead({
  title,
  lede,
  actions,
}: {
  title: string;
  lede?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="page-head">
      <div className="head-text">
        <h1>{title}</h1>
        {lede && <div className="lede">{lede}</div>}
      </div>
      {actions && <div className="head-actions">{actions}</div>}
    </header>
  );
}

// --- Field ---------------------------------------------------------------------------

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="field">
      <span className="label">{label}</span>
      {hint && <span className="hint">{hint}</span>}
      {children}
    </label>
  );
}

/** A labelled group of **several** controls. `Field`'s sibling, and not a variant of it.
 *
 *  `Field` is a `<label>`, which is right for one control and wrong for more than one: a
 *  `<label>` names exactly one thing, so every control inside a multi-control one inherits
 *  the same accessible name — and a **button** inside one is announced as the field's whole
 *  label rather than as what it does. That is not a rendering nicety. It is the difference
 *  between "Add" and "What it touches, a resource type and the argument that names one,
 *  this is what a grant is written against…" being read out to somebody who cannot see the
 *  screen.
 *
 *  **Found by a test that could not press a button.** 12c's vetting form is the first
 *  screen here with a label over a row of controls plus an action, and `getByRole("button",
 *  {name: "Add a resource"})` found nothing — because that button's name was the paragraph
 *  above it. Every previous use of `Field` wrapped exactly one input, so the bug had never
 *  had an opportunity.
 *
 *  So this is a `<div>` with a `<span>` that looks identical and names nothing, and the
 *  controls inside keep their own names. Use `Field` for one input; use this for a row, or
 *  for anything with a button in it.
 */
export function FieldGroup({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div className="field">
      <span className="label">{label}</span>
      {hint && <span className="hint">{hint}</span>}
      {children}
    </div>
  );
}

// --- Notice --------------------------------------------------------------------------

/** Something that happened and is worth a sentence. `bad` and `warn` carry
 *  `role="alert"` so a screen reader is told rather than left to find it.
 *
 *  **The glyph is a third signal, not a decoration.** The tone already carries a colour
 *  and the sentence carries the meaning; the shape is what is left for a reader who
 *  cannot tell this app's amber from its red, and a triangle is not a circle at any
 *  colour. It is `aria-hidden` like every other icon here — the sentence beside it is
 *  what gets read out. */
const NOTICE_GLYPH: Record<"info" | "warn" | "bad", IconName> = {
  info: "info",
  warn: "warn",
  bad: "alert",
};

export function Notice({
  tone = "info",
  title,
  children,
}: {
  tone?: "info" | "warn" | "bad";
  title?: string;
  children?: ReactNode;
}) {
  return (
    <div className={`notice ${tone}`} role={tone === "info" ? undefined : "alert"}>
      <span className="notice-icon">
        <Icon name={NOTICE_GLYPH[tone]} size={18} />
      </span>
      <div className="notice-body">
        {title && <h3>{title}</h3>}
        {children}
      </div>
    </div>
  );
}

// --- Empty ---------------------------------------------------------------------------

/** An empty result, stated as a fact.
 *
 *  It looks like a component with nothing in it and it is the opposite: in this product
 *  **absence is denial**, so "there is nothing here" is a true and complete answer to a
 *  question about access, not a failure to load. Anything that reads as breakage —
 *  a spinner that never stops, an error tone, the word "error" — invites somebody to
 *  raise a ticket about a system working exactly as designed. */
export function Empty({
  title,
  icon = "inbox",
  children,
}: {
  title: string;
  icon?: IconName;
  children?: ReactNode;
}) {
  return (
    <div className="empty">
      {/* Faint, small, and in a circle of the sunk colour. A large dark centred symbol
          is the visual grammar of an error page, and this screen is an answer. */}
      <span className="empty-icon">
        <Icon name={icon} size={20} />
      </span>
      <h2>{title}</h2>
      {children}
    </div>
  );
}

// --- Spinner -------------------------------------------------------------------------

export function Spinner({ label }: { label?: string }) {
  return (
    <>
      <span className="spinner" role="status" aria-label={label ?? "loading"} />
      {label && <span className="muted"> {label}</span>}
    </>
  );
}

// --- Skeleton ------------------------------------------------------------------------

/** A list that has not arrived yet, drawn as the shape of the list.
 *
 *  It replaces `Spinner` where the wait is a list of rows, for one reason: the page does
 *  not move when the rows land. A spinner is a different size from the thing it stands
 *  for, so every list in this app used to jump once on arrival.
 *
 *  It announces itself as `status` with the same label the spinner uses, so a screen
 *  reader is told "loading" either way and nothing has to know which one a page picked. */
export function Skeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="rows" role="status" aria-label="loading">
      {Array.from({ length: rows }, (_, i) => (
        <div className="row" key={i} aria-hidden="true">
          <span className="skeleton wide" />
          <span className="skeleton narrow" />
        </div>
      ))}
    </div>
  );
}

// --- Stats ---------------------------------------------------------------------------

export function Stats({
  items,
}: {
  items: {
    k: string;
    v: ReactNode;
    alert?: boolean;
    /** Where this tile's rows are. Step 066 — the tiles are the briefing, and a briefing
     *  whose numbers cannot be opened is where a reader stops. */
    href?: string;
    /** How this compares with the window before it. Step 066a — rendered under the
     *  value, in ink rather than in colour: a figure that went up is not good or bad
     *  until somebody says which number it is, and a green arrow says it for them. */
    delta?: ReactNode;
  }[];
}) {
  return (
    <div className="stats">
      {items.map((item) => {
        const body = (
          <>
            <span className="k">{item.k}</span>
            <span className="v">{item.v}</span>
            {item.delta ? <span className="delta">{item.delta}</span> : null}
          </>
        );
        return item.href ? (
          // The whole tile is the target, not the number inside it — a 4-character link
          // in a 12rem box is a target somebody misses.
          //
          // `Link`, never `<a href>`: the token lives in a module-scope variable, so a
          // full document navigation signs the reader out. See `charts.tsx`' `Mark`.
          <Link
            key={item.k}
            to={item.href}
            className={`stat linked${item.alert ? " alert" : ""}`}
          >
            {body}
          </Link>
        ) : (
          <div key={item.k} className={`stat${item.alert ? " alert" : ""}`}>
            {body}
          </div>
        );
      })}
    </div>
  );
}

// --- Block ---------------------------------------------------------------------------

/** Text the server wrote, shown exactly as it wrote it. Used for an answer, for a
 *  task, and for `error` — which on a cancelled run carries the guarantee in the words
 *  the audit trail supports. */
export function Block({ children }: { children: ReactNode }) {
  return <pre className="block">{children}</pre>;
}

// --- Tag -----------------------------------------------------------------------------

/** A tool or a resource. `write` is marked because the read/write annotation is the
 *  thing a connector admin sat down and made, and it is the one property of a tool that
 *  decides whether a mistake is recoverable. */
export function Tag({ write = false, children }: { write?: boolean; children: ReactNode }) {
  return <span className={`tag${write ? " write" : ""}`}>{children}</span>;
}

// --- Tabs ----------------------------------------------------------------------------

/** One pane of a `Tabs`. `label` is the strip; `id` is what goes in the URL. */
export type Tab = { id: string; label: string; panel: ReactNode };

/** A tab strip and the pane it selects. Step 048.
 *
 *  **The selected tab is not state this owns.** It is passed in and changed through
 *  `onSelect`, because on the one screen that needed tabs the selection belongs in the
 *  query string — this repo has said twice that *"a tab index is not a URL"*, and a
 *  component holding its own selection is how a tab set stops being addressable. A
 *  caller that genuinely wants local state can pass `useState`'s pair.
 *
 *  `active` naming a tab that is not in `tabs` falls back to the first rather than
 *  rendering nothing: the value arrives off a URL somebody can mistype, and a blank page
 *  is a worse answer than the front of the page.
 *
 *  **Keyboard: arrows move, and moving selects.** The strip is one tab stop
 *  (`tabIndex=-1` on the unselected buttons), and ←/→/Home/End move between them, which
 *  is the ARIA pattern for a tab set whose panes are already loaded. Nothing here is
 *  expensive to show, so automatic activation costs a reader nothing and saves them a
 *  keystroke per tab. */
export function Tabs({
  tabs,
  active,
  onSelect,
  label,
}: {
  tabs: Tab[];
  active: string;
  onSelect: (id: string) => void;
  label: string;
}) {
  if (!tabs.length) return null;
  const current = tabs.some((tab) => tab.id === active) ? active : tabs[0].id;
  const index = tabs.findIndex((tab) => tab.id === current);

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const moves: Record<string, number> = {
      ArrowLeft: index - 1,
      ArrowRight: index + 1,
      Home: 0,
      End: tabs.length - 1,
    };
    const next = moves[event.key];
    if (next === undefined) return;
    event.preventDefault();
    // Wraps, so ← on the first tab lands on the last rather than doing nothing.
    const target = tabs[(next + tabs.length) % tabs.length];
    onSelect(target.id);
    document.getElementById(`tab-${target.id}`)?.focus();
  };

  return (
    <>
      <div className="tabs" role="tablist" aria-label={label} onKeyDown={onKeyDown}>
        {tabs.map((tab) => {
          const selected = tab.id === current;
          return (
            <button
              key={tab.id}
              id={`tab-${tab.id}`}
              type="button"
              role="tab"
              className={`tab${selected ? " selected" : ""}`}
              aria-selected={selected}
              aria-controls={`panel-${tab.id}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => onSelect(tab.id)}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
      {tabs.map((tab) => (
        <div
          key={tab.id}
          id={`panel-${tab.id}`}
          role="tabpanel"
          aria-labelledby={`tab-${tab.id}`}
          // **Hidden, not unmounted.** The whole response is already in hand and every
          // figure is inline SVG over at most ninety points, so mounting all six costs
          // less than the machinery to avoid it — and a pane that unmounts loses its
          // open `Show the numbers` disclosures every time a reader looks away.
          hidden={tab.id !== current}
        >
          {tab.panel}
        </div>
      ))}
    </>
  );
}
