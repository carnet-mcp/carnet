/** Per-test isolation, and the two things a component test here would otherwise share.
 *
 * The same argument as `backend/tests/conftest.py`'s autouse fixtures: what is shared
 * between tests is what makes a suite stay green while it stops meaning anything. Here
 * that is the rendered DOM and whatever `fetch` a previous test installed.
 */

import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
