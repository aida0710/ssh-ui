import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Button, Card, Notice, Row } from "./surface";

describe("Row", () => {
  it("names its control through the label", () => {
    render(
      <Card>
        <Row label="HostName">
          <input defaultValue="bastion.eu.example.com" />
        </Row>
      </Card>,
    );

    expect(screen.getByLabelText("HostName")).toHaveValue("bastion.eu.example.com");
  });

  // ヒントは意図的に label 要素の外に置く。中に置くと、助言の文章
  // 丸ごとがコントロールの accessible name の一部になってしまう——
  // ui/form.tsx の `Field` が既に記録しているのと同じ過ちだ。
  it("keeps a hint out of the accessible name", () => {
    render(
      <Card>
        <Row label="Port" hint="OpenSSH defaults to 22 when this is unset.">
          <input defaultValue="22" />
        </Row>
      </Card>,
    );

    expect(screen.getByLabelText("Port")).toHaveValue("22");
    expect(screen.getByText("OpenSSH defaults to 22 when this is unset.")).toBeInTheDocument();
  });
});

describe("Row's trailing action", () => {
  // action は label 要素の外になければならない。中にあると、クリックした
  // 「Remove」が label を発火させ、代わりに input へフォーカスを移してしまう。
  it("is a control of its own, not part of the field's label", async () => {
    const onRemove = vi.fn();
    const user = userEvent.setup();
    render(
      <Card>
        <Row label="Port" action={<button type="button" onClick={onRemove}>Remove</button>}>
          <input defaultValue="22" />
        </Row>
      </Card>,
    );

    const field = screen.getByLabelText("Port");
    await user.click(screen.getByRole("button", { name: "Remove" }));

    expect(onRemove).toHaveBeenCalledOnce();
    expect(field).not.toHaveFocus();
    // そして action 自身の語は、フィールドの名前の外にとどまる。
    expect(screen.getByLabelText("Port")).toHaveValue("22");
  });
});

describe("Row's warning", () => {
  it("is amber and announced, where a hint is neither", () => {
    render(
      <Card>
        <Row label="ProxyCommand" warning="This directive runs a program.">
          <input defaultValue="/usr/bin/nc %h %p" />
        </Row>
      </Card>,
    );

    expect(screen.getByRole("status")).toHaveTextContent("This directive runs a program.");
    expect(screen.getByLabelText("ProxyCommand")).toHaveValue("/usr/bin/nc %h %p");
  });
});

describe("Notice", () => {
  it("announces itself as a status", () => {
    render(<Notice>This save rewrites three lines.</Notice>);

    expect(screen.getByRole("status")).toHaveTextContent("This save rewrites three lines.");
  });

  it("announces a destructive one as an alert", () => {
    render(<Notice tone="danger">This cannot be undone.</Notice>);

    expect(screen.getByRole("alert")).toHaveTextContent("This cannot be undone.");
  });
});

describe("Button", () => {
  it("is a button of type button unless told otherwise", () => {
    render(<Button>Save</Button>);

    expect(screen.getByRole("button", { name: "Save" })).toHaveAttribute("type", "button");
  });

  it("passes through disabled", () => {
    render(<Button disabled>Save</Button>);

    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  });
});
