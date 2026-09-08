/** Fetch on mount; refetch on demand. The whole of decision 6's machinery.
 *
 * There is no cache and nothing is shared between components. Two pages showing the
 * same run make two requests, and that is the intended trade: a shared copy is a cache,
 * a cache needs invalidation, and the first bug is a run whose status stopped updating.
 *
 * The one thing this does carefully is **not showing a spinner over data it already
 * has**. A polled run refetches every two seconds, and a `loading` flag that flipped on
 * every poll would make the page flicker for the entire life of the run. So `loading`
 * means *nothing to show yet*, and a refetch that fails leaves the last good value on
 * screen with the failure beside it rather than replacing it with an error page.
 *
 * ## The second thing, added by 035b: a stale answer never wins
 *
 * Every load takes a ticket, and an answer is thrown away if a newer load has started
 * since. Without it the hook resolves whichever request the network happens to finish
 * last, which is not the same as the one that was asked most recently.
 *
 * **This was latent until a page changed its own deps.** Every caller before 035b passed
 * deps that only change on navigation, where the slow answer belongs to a screen nobody
 * is looking at any more. `DenialsPage` puts a filter in the deps, so two clicks are two
 * requests a few milliseconds apart — and a log view that renders the *first* one's rows
 * under the *second* one's selected filter is not showing stale data, it is answering a
 * question it was not asked. Driven out by clicking two filters with the first request
 * held open; see `useResource.test.tsx`.
 *
 * `replace` takes a ticket too, which settles the same race for `RunDetailPage`: its
 * wait loop pushes each snapshot through `replace` and calls `reload` only on the error
 * path, so a `reload` in flight when a fresher snapshot arrives must not overwrite it.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export interface Resource<T> {
  data: T | null;
  error: unknown;
  /** True only until the first answer, success or failure. */
  loading: boolean;
  reload: () => void;
  /** Push a value fetched outside `load` — the run page's wait loop (step 032) hands
   *  each returned snapshot through here so `loading` and the last-good-value rule
   *  keep applying. It clears `error`: a pushed value *is* a successful read. */
  replace: (value: T) => void;
}

export function useResource<T>(load: () => Promise<T>, deps: unknown[]): Resource<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);

  // The latest `load`, without making it a dependency: an inline arrow is a new
  // function on every render, and a hook that refetched on every render would poll as
  // fast as React re-renders.
  const latest = useRef(load);
  latest.current = load;

  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  // The ticket the newest load holds. Bumped by anything that supersedes an in-flight
  // request — a fresh `reload`, or a value pushed through `replace` — so an older answer
  // arriving late is dropped rather than applied over a newer one.
  const ticket = useRef(0);

  const reload = useCallback(() => {
    const mine = ++ticket.current;
    const current = () => alive.current && mine === ticket.current;

    latest
      .current()
      .then((value) => {
        if (!current()) return;
        setData(value);
        setError(null);
      })
      .catch((cause: unknown) => {
        // A superseded request's *failure* is dropped for the same reason its success
        // is: it is the answer to a question that is no longer on screen, and rendering
        // it would put a failure beside data that loaded perfectly well.
        if (!current()) return;
        setError(cause);
      })
      .finally(() => {
        if (current()) setLoading(false);
      });
  }, []);

  const replace = useCallback((value: T) => {
    if (!alive.current) return;
    ticket.current += 1;
    setData(value);
    setError(null);
    setLoading(false);
  }, []);

  useEffect(() => {
    setLoading(true);
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading, reload, replace };
}
