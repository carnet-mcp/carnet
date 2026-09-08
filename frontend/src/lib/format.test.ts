/** The one formatter that does not render in the reader's zone. Step 022b.
 *
 * `at`, `on` and `elapsed` have never had a test file, and that is defensible: they wrap
 * `toLocaleString` with no branch worth pinning, and asserting their output would assert
 * the machine's locale.
 *
 * **035f added `day` and `passed`, and they are tested for `inZone`'s reason rather than
 * `on`'s.** What is pinned is not the format — that is still the machine's locale — but
 * the two properties a reader's decision turns on: that a year is present, and which of
 * *expired* and *expires* gets said. `on` omitting the year is asserted here too, because
 * it is the difference the new function exists for and a well-meant edit to either could
 * quietly erase it.
 *
 * `inZone` is different in exactly the way that matters. Its whole job is to *ignore*
 * the machine it runs on, so a test can name the answer — and the failure it guards
 * against is silent: a schedule rendered in the reader's zone looks like a perfectly
 * good time. It is simply somebody else's.
 */

import { describe, expect, it } from "vitest";

import { browserZone, day, inZone, on, passed , prettyIfJsonObject, tokens } from "./format";

// 07:30 in Berlin on a summer morning, as the UTC instant the API sends.
const BERLIN_MORNING = "2026-08-13T05:30:00+00:00";

describe("a schedule's next fire, in the schedule's own zone", () => {
  it("renders the wall time somebody typed, not the reader's", () => {
    // Whatever zone this machine is in, the answer is 07:30 — which is the point.
    expect(inZone(BERLIN_MORNING, "Europe/Berlin")).toContain("07:30");
    expect(inZone(BERLIN_MORNING, "UTC")).toContain("05:30");
  });

  it("names the zone beside the time, because 07:30 alone is the same lie", () => {
    // Without an abbreviation the reader cannot tell whose clock they are reading, which
    // is the ambiguity they opened the card to resolve.
    //
    // Asserted against the same rendering **minus the label**, built here, rather than
    // against a literal like "GMT+2": the abbreviation is locale-dependent and a test
    // that pinned one would pass or fail on where it ran. Found by a mutation that
    // dropped `timeZoneName` and survived a weaker assertion.
    const withoutLabel = new Date(BERLIN_MORNING).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      timeZone: "Europe/Berlin",
    });
    const rendered = inZone(BERLIN_MORNING, "Europe/Berlin");

    expect(rendered).not.toBe(withoutLabel);
    expect(rendered.length).toBeGreaterThan(withoutLabel.length);
    expect(rendered).not.toBe(inZone(BERLIN_MORNING, "UTC"));
  });

  it("handles a zone whose offset is not a whole hour", () => {
    // Kathmandu is +05:45. A formatter doing its own arithmetic gets this wrong; one
    // handing the zone to `Intl` does not.
    expect(inZone(BERLIN_MORNING, "Asia/Kathmandu")).toContain("11:15");
  });

  it("keeps the same wall time across a DST transition, which is the whole feature", () => {
    // 07:30 Berlin the day before the autumn fold, and the day after. Same wall time,
    // different UTC instants — a screen that added an hour would show 06:30 on one of
    // them and quietly contradict the server's own arithmetic.
    expect(inZone("2026-10-24T05:30:00+00:00", "Europe/Berlin")).toContain("07:30");
    expect(inZone("2026-10-26T06:30:00+00:00", "Europe/Berlin")).toContain("07:30");
  });

  it("falls back to the reader's zone rather than throwing on a zone it cannot load", () => {
    // A row whose zone this browser cannot resolve is still a row somebody needs to read
    // and delete. Throwing would take the whole card down with it.
    expect(inZone(BERLIN_MORNING, "Mars/Olympus")).not.toBe("");
  });

  it("says nothing about a moment that has not happened", () => {
    expect(inZone("", "Europe/Berlin")).toBe("");
  });
});

describe("the timezone a form prefills", () => {
  it("is a zone name, so the field a person must confirm starts from something real", () => {
    // Asserted as a shape rather than a value: this test runs on somebody's laptop and
    // in CI, and those are two different zones. What must hold is that the prefill is a
    // key `inZone` can use rather than an empty field or a raw offset.
    const zone = browserZone();
    expect(inZone(BERLIN_MORNING, zone)).not.toBe("");
  });
});


describe("a date with its year, for a fact that is not about today", () => {
  // `day()` exists because `on()` does not show one. That is right for a run listing,
  // where everything is recent, and wrong for an expiry — see `ConnectionsPage.lapse`.

  it("shows the year, which `on` never does", () => {
    expect(day("2020-06-15T12:00:00Z")).toMatch(/2020/);
    expect(on("2020-06-15T12:00:00Z")).not.toMatch(/2020/);
  });

  it("keeps two far-apart instants apart", () => {
    // The failure this replaced: a credential that expired in 2020 and one expiring in
    // 2099 rendered identically enough that a reader would take the first for last
    // December.
    expect(day("2020-03-04T10:00:00Z")).not.toBe(day("2099-03-04T10:00:00Z"));
  });

  it("carries no time of day, because the hour was never the question", () => {
    expect(day("2027-01-02T13:45:00Z")).not.toMatch(/45/);
  });

  it("says nothing about a moment that has not happened", () => {
    expect(day("")).toBe("");
  });

  it("hands back an unparseable value rather than rendering 'Invalid Date'", () => {
    expect(day("not-a-date")).toBe("not-a-date");
  });
});

describe("whether an instant has passed", () => {
  it("is true for the past and false for the future", () => {
    expect(passed("2020-01-01T00:00:00Z")).toBe(true);
    expect(passed("2099-01-01T00:00:00Z")).toBe(false);
  });

  it("is false for anything unparseable, which is the quieter wrong answer", () => {
    // A garbage stamp is a server or migration problem. Rendering it as *expired* would
    // send somebody to reconnect a credential that is probably fine.
    expect(passed("not-a-date")).toBe(false);
    expect(passed("")).toBe(false);
  });
});

/** Step 035i. The third clause of 024's register row: the run page renders a JSON answer
 *  as plain text in the Block. */
describe("an answer that is a JSON object", () => {
  it("is indented", () => {
    expect(prettyIfJsonObject('{"summary":"two open","severity":"low"}')).toBe(
      '{\n  "summary": "two open",\n  "severity": "low"\n}',
    );
  });

  it("survives whitespace around it", () => {
    expect(prettyIfJsonObject('\n  {"a":1}  \n')).toBe('{\n  "a": 1\n}');
  });

  it("leaves prose exactly as it came", () => {
    const prose = "There are two open issues.\n\n  - one\n  - two\n";
    expect(prettyIfJsonObject(prose)).toBe(prose);
  });

  it("leaves every JSON value that is not an object alone", () => {
    // Object-rooted only, which is the platform's own rule rather than a new one: a
    // schema must be rooted at an object, "and a consumer of a bare string had no need of
    // a schema". An array of results is valid JSON and is not what this exists for.
    for (const text of ['["a","b"]', '"just a string"', "42", "true", "null"]) {
      expect(prettyIfJsonObject(text)).toBe(text);
    }
  });

  it("leaves a prose answer that merely starts with a brace alone", () => {
    // The cheap gate lets this through to `JSON.parse`, which throws, which returns the
    // input. Nothing is ever lost by a parse failure.
    const said = "{ this is not JSON, it is a sentence about braces";
    expect(prettyIfJsonObject(said)).toBe(said);
  });

  it("returns the empty string for an empty answer", () => {
    expect(prettyIfJsonObject("")).toBe("");
  });
});

describe("a token count", () => {
  it("says nothing rather than zero for a run nobody measured", () => {
    // The assertion this file exists for, on this function. `0` on these columns means
    // *unmeasured* — a run from before the counters, or one that never reached a model
    // call — and it can never mean *free*, because no model reply is. Rendering a
    // literal 0 would put the impossible reading on the screen.
    expect(tokens(0)).toBe("—");
  });

  it("is exact below a thousand and rounded above it", () => {
    expect(tokens(1)).toBe("1");
    expect(tokens(999)).toBe("999");
    expect(tokens(1_000)).toBe("1.0k");
    expect(tokens(12_400)).toBe("12.4k");
    expect(tokens(999_999)).toBe("1000.0k");
    expect(tokens(1_240_000)).toBe("1.24M");
  });
});
