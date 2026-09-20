/** A log read newest first, one page at a time, with *show older*. 110f, plan 107 D10.
 *
 *  The three log pages shared one shape for twenty steps: the newest two hundred rows,
 *  oldest first, and a hint that older records were not shown. The row somebody came
 *  for was at the bottom of that window, and anything before it was unreachable from a
 *  browser — noticed on the audit log by the first administrator who needed it, which
 *  is the evidence 12b said pagination would wait for.
 *
 *  ## The cursor is a row's id, never a page number
 *
 *  `older()` asks the server for the rows before the **oldest id on screen**. An offset
 *  would drift: a row appended between two requests shifts every offset by one, and
 *  page two would repeat the last row of page one or skip the first row it should have
 *  shown. An id does not move. The rows already on screen are kept and the older page
 *  is appended beneath them, so the reader's place is not lost when they reach for
 *  more.
 *
 *  ## `more` is known, not guessed — one row over the page
 *
 *  The routes report no total, so *is there another page* has no direct answer. This
 *  asks for **one row more than it shows**: the extra row is not rendered, and its
 *  existence is the answer. A log of exactly two hundred rows offers *Show older* once
 *  and then stops, rather than offering a click that comes back with nothing — which is
 *  what a short-page guess does on every log whose length is a multiple of the page.
 *
 *  Trimming cannot open a gap. The cursor is the smallest id **shown**, so the row that
 *  was trimmed is the first row of the next page: fetched twice, rendered once. A count
 *  request per load would be a second query for a number nobody reads; one extra row is
 *  the same query, one row wider.
 *
 *  ## Filters reset the log, not the page
 *
 *  `deps` are the filters. A change to any of them starts over from the newest rows —
 *  appending a filtered page beneath an unfiltered one would be a list that is two
 *  different questions' answers. `useResource`'s ticket rule applies: an older answer
 *  arriving after a newer request is dropped rather than rendered over it.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export interface PagedLog<T extends { id: number }> {
  rows: T[] | null;
  error: unknown;
  /** True until the first page has answered, success or failure. */
  loading: boolean;
  /** Whether *show older* is offered: the last page came back full. */
  more: boolean;
  /** True while an older page is on its way. */
  fetching: boolean;
  older: () => void;
}

export function usePagedLog<T extends { id: number }>(
  load: (before: number | undefined, limit: number) => Promise<T[]>,
  pageSize: number,
  deps: unknown[],
): PagedLog<T> {
  const [rows, setRows] = useState<T[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [more, setMore] = useState(false);
  const [fetching, setFetching] = useState(false);

  const latest = useRef(load);
  latest.current = load;

  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  // The ticket the newest request holds; a filter change bumps it so a page requested
  // under the old filters is dropped when it lands.
  const ticket = useRef(0);

  const fetchPage = useCallback(
    (before: number | undefined, previous: T[]) => {
      const mine = ++ticket.current;
      const current = () => alive.current && mine === ticket.current;
      setFetching(true);
      latest
        // One row more than is shown: see the docstring. The server caps `limit` in its
        // own signature, and a page of a hundred plus one is nowhere near it.
        .current(before, pageSize + 1)
        .then((page) => {
          if (!current()) return;
          setRows([...previous, ...page.slice(0, pageSize)]);
          setMore(page.length > pageSize);
          setError(null);
        })
        .catch((cause: unknown) => {
          if (!current()) return;
          setError(cause);
        })
        .finally(() => {
          if (!current()) return;
          setLoading(false);
          setFetching(false);
        });
    },
    [pageSize],
  );

  useEffect(() => {
    setLoading(true);
    setRows(null);
    setMore(false);
    fetchPage(undefined, []);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  const older = useCallback(() => {
    if (!rows || rows.length === 0 || fetching) return;
    const oldest = Math.min(...rows.map((row) => row.id));
    fetchPage(oldest, rows);
  }, [rows, fetching, fetchPage]);

  return { rows, error, loading, more, fetching, older };
}
