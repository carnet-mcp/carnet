import { Component, type ReactNode } from "react";

import { Notice } from "./ui";

/** The floor under every screen: a page that throws becomes a sentence, not a blank tab.
 *
 * Until this existed there was no error boundary anywhere in the app, so any component
 * that threw during render unmounted the React root — 023b's testing pass watched a
 * malformed create response do exactly that at the one instant the only copy of a
 * trigger secret was on screen. That specific path is checked at its cause now; this is
 * the general property.
 *
 * **One boundary at the page, deliberately, rather than one per card.** The register row
 * offered either. Page-level is one wrap in `AppShell` that covers every screen this app
 * has and every screen it grows, and it keeps the frame alive — the nav still works, so
 * the person is one click from a page that renders. Per-card granularity is a
 * screen-by-screen judgment with nothing yet to judge it against, and a wrapping idiom
 * started now would spread by copy into screens that get nothing from it. The first real
 * card crash is the evidence that decision wants.
 *
 * A class, because React has no hook for catching a child's render throw —
 * `getDerivedStateFromError` is the whole reason this is the codebase's only class
 * component.
 */
export default class Boundary extends Component<
  { children: ReactNode },
  { caught: boolean; error: unknown }
> {
  // `caught` is a separate flag because `throw null` is legal and would make the error
  // value indistinguishable from the initial state.
  state = { caught: false, error: null as unknown };

  static getDerivedStateFromError(error: unknown) {
    return { caught: true, error };
  }

  render() {
    if (!this.state.caught) return this.props.children;
    const { error } = this.state;
    return (
      <Notice tone="bad" title="This page failed to render">
        <p className="sentence">
          {error instanceof Error ? error.message : String(error)}
        </p>
        <p className="muted">
          Nothing has been lost — this is a defect in the page, not in your data. The
          links above still work, and reloading may bring the page back.
        </p>
      </Notice>
    );
  }
}
