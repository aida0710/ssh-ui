import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
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

  // The hint sits outside the label element on purpose. Inside it, a whole
  // sentence of advice became part of the control's accessible name — the same
  // mistake `Field` in ui/form.tsx already documents.
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
