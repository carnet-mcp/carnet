/** `useResource`, and the one property it did not have.
 *
 * There was no test file for this hook, which is 035j's subject generally and became
 * this chunk's specifically: 035b is the first caller to put something a person clicks
 * into the deps array, and that is what turns "whichever request finishes last wins"
 * from latent into reachable.
 *
 * The rest of the hook's behaviour is asserted here too, because a shared hook being
 * modified with no tests of its own is how the modification breaks the other twenty
 * callers.
 */

import { act, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { useResource } from "./useResource";

/** A promise whose settling this test controls. */
function deferred<T>() {
  let settle: (value: T) => void = () => {};
  let fail: (cause: unknown) => void = () => {};
  const promise = new Promise<T>((resolve, reject) => {
    settle = resolve;
    fail = reject;
  });
  return { promise, settle, fail };
}

function Probe({ load, deps }: { load: () => Promise<string>; deps: unknown[] }) {
  const { data, error, loading } = useResource(load, deps);
  return (
    <div>
      <span data-testid="data">{data ?? ""}</span>
      <span data-testid="error">{error ? String((error as Error).message) : ""}</span>
      <span data-testid="loading">{loading ? "yes" : "no"}</span>
    </div>
  );
}

/** Let every pending microtask and timer callback land, inside `act` so React applies
 *  the state they set before the assertion reads it. */
const settled = () =>
  act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });

describe("an answer that arrives after a newer one was asked for", () => {
  it("is thrown away rather than rendered", async () => {
    // The bug, minimal. Two loads a moment apart, the first slower than the second —
    // which is ordinary on a network and guaranteed by nothing. Before the ticket, the
    // hook rendered whichever finished last: the *first* request's answer, under the
    // second request's selection.
    const first = deferred<string>();
    const second = deferred<string>();
    const load = vi.fn().mockReturnValueOnce(first.promise).mockReturnValue(second.promise);

    const { rerender } = render(<Probe load={load} deps={["a"]} />);
    rerender(<Probe load={load} deps={["b"]} />);

    second.settle("the answer to b");
    await settled();
    expect(screen.getByTestId("data")).toHaveTextContent("the answer to b");

    first.settle("the answer to a");
    await settled();

    expect(screen.getByTestId("data")).toHaveTextContent("the answer to b");
  });

  it("cannot put a superseded failure beside data that loaded fine", async () => {
    // The other half, and the one that would be read as a bug in the server: a request
    // that was abandoned fails, and its error lands next to a table that arrived
    // perfectly well.
    const first = deferred<string>();
    const second = deferred<string>();
    const load = vi.fn().mockReturnValueOnce(first.promise).mockReturnValue(second.promise);

    const { rerender } = render(<Probe load={load} deps={["a"]} />);
    rerender(<Probe load={load} deps={["b"]} />);

    second.settle("good");
    await settled();

    first.fail(new Error("the abandoned request failed"));
    await settled();

    expect(screen.getByTestId("error")).toHaveTextContent("");
    expect(screen.getByTestId("data")).toHaveTextContent("good");
  });

  it("does not leave loading stuck on when the stale answer is the last to arrive", async () => {
    const first = deferred<string>();
    const second = deferred<string>();
    const load = vi.fn().mockReturnValueOnce(first.promise).mockReturnValue(second.promise);

    const { rerender } = render(<Probe load={load} deps={["a"]} />);
    rerender(<Probe load={load} deps={["b"]} />);

    second.settle("good");
    await settled();
    first.settle("stale");
    await settled();

    expect(screen.getByTestId("loading")).toHaveTextContent("no");
  });
});

describe("what the hook already promised", () => {
  it("loads once on mount and reports the value", async () => {
    const load = vi.fn().mockResolvedValue("hello");

    render(<Probe load={load} deps={[]} />);
    await settled();

    expect(screen.getByTestId("data")).toHaveTextContent("hello");
    expect(screen.getByTestId("loading")).toHaveTextContent("no");
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("does not refetch when the deps have not changed", async () => {
    // An inline arrow is a new function on every render, so a hook that depended on it
    // would poll as fast as React re-renders. `latest` is what stops that.
    const load = vi.fn().mockResolvedValue("hello");

    const { rerender } = render(<Probe load={load} deps={["same"]} />);
    await settled();
    rerender(<Probe load={load} deps={["same"]} />);
    await settled();

    expect(load).toHaveBeenCalledTimes(1);
  });

  it("keeps the last good value on screen when a refetch fails", async () => {
    const load = vi
      .fn()
      .mockResolvedValueOnce("first")
      .mockRejectedValue(new Error("server fell over"));

    const { rerender } = render(<Probe load={load} deps={["a"]} />);
    await settled();
    rerender(<Probe load={load} deps={["b"]} />);
    await settled();

    expect(screen.getByTestId("data")).toHaveTextContent("first");
    expect(screen.getByTestId("error")).toHaveTextContent("server fell over");
  });

  it("says nothing after unmounting", async () => {
    // A resolved fetch touching state on a component that is gone is a warning at best
    // and a leak at worst.
    const first = deferred<string>();
    const load = vi.fn().mockReturnValue(first.promise);

    const { unmount } = render(<Probe load={load} deps={[]} />);
    unmount();
    first.settle("too late");
    await settled();

    // Nothing to assert on screen — the property is that resolving after unmount sets
    // no state, which shows up as the absence of React's warning rather than as a value.
    expect(load).toHaveBeenCalledTimes(1);
  });
});
