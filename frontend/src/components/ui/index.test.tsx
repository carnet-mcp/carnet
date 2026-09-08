/** The primitives, where they carry a decision.
 *
 * Most of this kit is a class name around its children and is tested by every screen that
 * uses it. What earns a test here is a decision: `Button` renders two different elements,
 * and the whole reason it grew a `to` form was that five call sites had hand-written the
 * class and got a `<Link>` that only *looked* like a button. Since 035j the others with a
 * decision are pinned too — `Notice`'s alert roles, `FieldGroup` existing so a button
 * keeps its own name, `Badge`'s word-never-colour-alone rule, and `Empty` being a fact
 * rather than a failure.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import { Badge, Button, Empty, Field, FieldGroup, Notice, Skeleton, Tag } from "./index";

function show(ui: React.ReactNode) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

describe("Button", () => {
  it("is a link, with an href, when it is given somewhere to go", () => {
    // The property the hand-written `<Link className="btn">` had and a `<button>` with an
    // onClick does not: a middle click opens it in a tab, and a screen reader says it
    // navigates rather than that it acts.
    show(
      <Button kind="primary" to="/agents/new">
        New agent
      </Button>,
    );

    const link = screen.getByRole("link", { name: "New agent" });
    expect(link).toHaveAttribute("href", "/agents/new");
    expect(link).toHaveClass("btn", "primary");
  });

  it("is a button, and presses, when it is given something to do", async () => {
    const onClick = vi.fn();
    show(<Button onClick={onClick}>Delete</Button>);

    await userEvent.click(screen.getByRole("button", { name: "Delete" }));

    expect(onClick).toHaveBeenCalledOnce();
  });

  it("refuses to be pressed while it is busy", async () => {
    const onClick = vi.fn();
    show(
      <Button busy onClick={onClick}>
        Saving
      </Button>,
    );

    const button = screen.getByRole("button", { name: /Saving/ });
    expect(button).toBeDisabled();
    await userEvent.click(button);
    expect(onClick).not.toHaveBeenCalled();
  });
});

describe("Skeleton", () => {
  it("says it is loading, in the words the spinner uses", () => {
    // A page may show either one. Neither should change what a screen reader is told.
    show(<Skeleton rows={2} />);

    expect(screen.getByRole("status", { name: "loading" })).toBeInTheDocument();
  });
});

// The additions below are 035j's: the primitives whose few lines carry a decision,
// pinned here once instead of implicitly by whichever screen happens to render them.

describe("Notice", () => {
  it("is an alert when it warns or accuses, and not when it merely informs", () => {
    // `bad` and `warn` interrupt a screen reader; `info` must not, or every hint on a
    // form becomes an announcement.
    const { rerender } = render(<Notice tone="bad" title="It broke" />);
    expect(screen.getByRole("alert")).toBeInTheDocument();

    rerender(<Notice tone="warn" title="It might" />);
    expect(screen.getByRole("alert")).toBeInTheDocument();

    rerender(<Notice tone="info" title="It is" />);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("FieldGroup", () => {
  it("leaves a button inside it its own name — the bug Field had and this exists to fix", () => {
    // A `<label>` names every control inside it, so a button inside `Field` was
    // announced as the field's whole paragraph. 12c's vetting form found it when
    // getByRole("button", {name: "Add a resource"}) found nothing.
    render(
      <FieldGroup label="What it touches" hint="a resource type and the argument">
        <input aria-label="resource" />
        <button>Add a resource</button>
      </FieldGroup>,
    );

    expect(screen.getByRole("button", { name: "Add a resource" })).toBeInTheDocument();
  });

  it("while Field names its one control with the label, which is its whole job", () => {
    render(
      <Field label="Name">
        <input />
      </Field>,
    );

    expect(screen.getByLabelText("Name")).toBeInTheDocument();
  });
});

describe("Badge and Tag", () => {
  it("carries its meaning as a word, with the colour pip hidden from a reader", () => {
    // "Never a colour alone": the word is the accessible content, the pip decoration.
    render(<Badge tone="bad">revoked</Badge>);

    expect(screen.getByText("revoked")).toBeInTheDocument();
    const pip = document.querySelector(".pip");
    expect(pip).toHaveAttribute("aria-hidden", "true");
  });

  it("marks a write Tag with the class the stylesheet alarms on", () => {
    render(<Tag write>post_message</Tag>);

    expect(screen.getByText("post_message")).toHaveClass("tag", "write");
  });
});

describe("Empty", () => {
  it("is a stated fact with a heading, not a spinner or an error", () => {
    render(<Empty title="Nothing has been refused yet" />);

    expect(
      screen.getByRole("heading", { name: "Nothing has been refused yet" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
