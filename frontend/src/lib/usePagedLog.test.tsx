/** `usePagedLog`, and the four ways a paging hook goes wrong quietly.
 *
 * The three log pages share this hook, so a defect here is a defect on all of them —
 * and every one of these is invisible on a screen that loads once and is left alone.
 * The page tests drive the hook through a rendered log; this drives it directly,
 * because *what it asked the server for* and *what it did with an answer that arrived
 * late* are properties of the hook rather than of any table.
 */

import { act, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { usePagedLog } from "./usePagedLog";

type Row = { id: number };

function deferred<T>() {
  let settle: (value: T) => void = () => {};
  let fail: (cause: unknown) => void = () => {};
  const promise = new Promise<T>((resolve, reject) => {
    settle = resolve;
    fail = reject;
  });
  return { promise, settle, fail };
}

/** `count` rows, newest first, as a log route answers. */
function page(from: number, count: number): Row[] {
  return Array.from({ length: count }, (_, i) => ({ id: from - i }));
}

function Probe({
  load,
  deps,
  size = 3,
}: {
  load: (before: number | undefined, limit: number) => Promise<Row[]>;
  deps: unknown[];
  size?: number;
}) {
  const { rows, error, loading, more, fetching, older } = usePagedLog(load, size, deps);
  return (
    <div>
      <span data-testid="ids">{(rows ?? []).map((r) => r.id).join(",")}</span>
      <span data-testid="state">{rows === null ? "null" : "rows"}</span>
      <span data-testid="error">{error ? String((error as Error).message) : ""}</span>
      <span data-testid="loading">{loading ? "yes" : "no"}</span>
      <span data-testid="more">{more ? "yes" : "no"}</span>
      <span data-testid="fetching">{fetching ? "yes" : "no"}</span>
      <button type="button" onClick={older}>
        older
      </button>
    </div>
  );
}

const settled = () =>
  act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });

const ids = () => screen.getByTestId("ids").textContent;
const older = () => act(() => void screen.getByRole("button").click());

describe("the first page", () => {
  it("asks for one row more than it shows, and shows the page", async () => {
    const load = vi.fn().mockResolvedValue(page(100, 4));
    render(<Probe load={load} deps={[]} />);
    await settled();

    // Three shown, four asked for: the fourth is the answer to *is there more*, and
    // rendering it would put a row on screen that the next page will also carry.
    expect(load).toHaveBeenCalledWith(undefined, 4);
    expect(ids()).toBe("100,99,98");
    expect(screen.getByTestId("more").textContent).toBe("yes");
    expect(screen.getByTestId("loading").textContent).toBe("no");
  });

  it("offers nothing older when the log ends exactly on a page boundary", async () => {
    // The case a short-page guess gets wrong, and the reason for the extra row: a log
    // of exactly three rows is a full page, and there is nothing behind it.
    const load = vi.fn().mockResolvedValue(page(100, 3));
    render(<Probe load={load} deps={[]} />);
    await settled();

    expect(ids()).toBe("100,99,98");
    expect(screen.getByTestId("more").textContent).toBe("no");
  });

  it("tells an empty log apart from a log still loading", async () => {
    const load = vi.fn().mockResolvedValue([]);
    render(<Probe load={load} deps={[]} />);

    expect(screen.getByTestId("state").textContent).toBe("null");
    await settled();
    expect(screen.getByTestId("state").textContent).toBe("rows");
    expect(ids()).toBe("");
    expect(screen.getByTestId("more").textContent).toBe("no");
  });
});

describe("turning the page", () => {
  it("asks for the rows before the SMALLEST id shown, and appends them", async () => {
    const load = vi
      .fn()
      .mockResolvedValueOnce(page(100, 4))
      .mockResolvedValueOnce(page(97, 2));
    render(<Probe load={load} deps={[]} />);
    await settled();

    older();
    await settled();

    // 98 is the smallest id shown; 97 — the row trimmed from the first answer — is the
    // first row of this page. Fetched twice, rendered once, and no gap between them.
    expect(load).toHaveBeenLastCalledWith(98, 4);
    expect(ids()).toBe("100,99,98,97,96");
    expect(screen.getByTestId("more").textContent).toBe("no");
  });

  it("takes the smallest id rather than the last row, so an out-of-order page is safe", async () => {
    // The hook must not assume the server's ordering. If it took `rows[rows.length - 1]`
    // it would page from whatever happened to be last, and a page that arrived in any
    // other order would skip everything between.
    const load = vi
      .fn()
      .mockResolvedValueOnce([{ id: 50 }, { id: 80 }, { id: 90 }, { id: 99 }])
      .mockResolvedValueOnce([]);
    render(<Probe load={load} deps={[]} />);
    await settled();

    older();
    await settled();

    expect(load).toHaveBeenLastCalledWith(50, 4);
  });

  it("ignores a second click while a page is already on its way", async () => {
    const first = deferred<Row[]>();
    const load = vi
      .fn()
      .mockResolvedValueOnce(page(100, 4))
      .mockReturnValueOnce(first.promise);
    render(<Probe load={load} deps={[]} />);
    await settled();

    older();
    older();
    older();
    await settled();

    // One request, not three — a double click on *Show older* must not fetch the same
    // page three times and append it three times.
    expect(load).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId("fetching").textContent).toBe("yes");

    first.settle(page(97, 1));
    await settled();
    expect(ids()).toBe("100,99,98,97");
  });

  it("does nothing at all on an empty log", async () => {
    const load = vi.fn().mockResolvedValue([]);
    render(<Probe load={load} deps={[]} />);
    await settled();

    older();
    await settled();

    expect(load).toHaveBeenCalledTimes(1);
  });
});

describe("an answer that is no longer the answer to anything", () => {
  it("is dropped when the filters changed while it was in flight", async () => {
    // The `useResource` defect, one hook further on and worse: there, a late answer
    // replaced the rows. Here it would be **appended** to a page that is now a
    // different question's answer — a table holding two filters' rows at once.
    const stale = deferred<Row[]>();
    const load = vi
      .fn()
      .mockReturnValueOnce(stale.promise)
      .mockResolvedValue(page(50, 2));

    const { rerender } = render(<Probe load={load} deps={["tool=a"]} />);
    rerender(<Probe load={load} deps={["tool=b"]} />);
    await settled();

    expect(ids()).toBe("50,49");

    stale.settle(page(999, 4));
    await settled();

    expect(ids()).toBe("50,49");
  });

  it("drops an older page that lands after the filters moved", async () => {
    const late = deferred<Row[]>();
    const load = vi
      .fn()
      .mockResolvedValueOnce(page(100, 4))
      .mockReturnValueOnce(late.promise)
      .mockResolvedValue(page(20, 1));

    const { rerender } = render(<Probe load={load} deps={["a"]} />);
    await settled();
    older();
    rerender(<Probe load={load} deps={["b"]} />);
    await settled();

    expect(ids()).toBe("20");

    late.settle(page(97, 2));
    await settled();

    // The page nobody is looking at any more does not get appended under the new one.
    expect(ids()).toBe("20");
  });

  it("starts the log over when the filters change, rather than appending", async () => {
    const load = vi
      .fn()
      .mockResolvedValueOnce(page(100, 4))
      .mockResolvedValueOnce(page(9, 2));

    const { rerender } = render(<Probe load={load} deps={["a"]} />);
    await settled();
    rerender(<Probe load={load} deps={["b"]} />);
    await settled();

    expect(ids()).toBe("9,8");
    expect(load).toHaveBeenLastCalledWith(undefined, 4);
  });
});

describe("a request that fails", () => {
  it("reports the failure and shows no rows, when it was the first page", async () => {
    const load = vi.fn().mockRejectedValue(new Error("the server said no"));
    render(<Probe load={load} deps={[]} />);
    await settled();

    expect(screen.getByTestId("error").textContent).toBe("the server said no");
    expect(screen.getByTestId("state").textContent).toBe("null");
    expect(screen.getByTestId("loading").textContent).toBe("no");
  });

  it("keeps the rows already read when it was an older page", async () => {
    // Losing the page somebody is reading because the page *behind* it failed would be
    // the worst outcome available here: they still have what they came for.
    const load = vi
      .fn()
      .mockResolvedValueOnce(page(100, 4))
      .mockRejectedValueOnce(new Error("gone"));
    render(<Probe load={load} deps={[]} />);
    await settled();

    older();
    await settled();

    expect(ids()).toBe("100,99,98");
    expect(screen.getByTestId("error").textContent).toBe("gone");
    expect(screen.getByTestId("fetching").textContent).toBe("no");
  });

  it("can be tried again after a failure, from the same cursor", async () => {
    const load = vi
      .fn()
      .mockResolvedValueOnce(page(100, 4))
      .mockRejectedValueOnce(new Error("gone"))
      .mockResolvedValueOnce(page(97, 1));
    render(<Probe load={load} deps={[]} />);
    await settled();

    older();
    await settled();
    older();
    await settled();

    expect(load).toHaveBeenLastCalledWith(98, 4);
    expect(ids()).toBe("100,99,98,97");
  });
});
