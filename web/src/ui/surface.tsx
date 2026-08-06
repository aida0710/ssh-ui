import type { ButtonHTMLAttributes, ReactNode } from "react";
import { dangerAction, hintText, primaryAction, secondaryAction } from "./form";

// An inset card of rows, the way macOS System Settings groups related
// settings: a hairline between rows, a border around the group, and the
// group's own explanation underneath rather than inside.
export function Card({ children }: { children: ReactNode }) {
  return <div className="overflow-hidden rounded-xl border border-line bg-card">{children}</div>;
}

// One setting: its name on the left, its control on the right.
//
// The label element wraps the control rather than pointing at it by id, which
// is how every form in this application already associates the two, so the
// accessible name needs no id to be unique across a page that may show the
// same keyword for two hosts.
export function Row({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <div className="border-t border-hairline first:border-t-0">
      <label className="flex items-center gap-3 px-3 py-2">
        <span className="w-32 shrink-0 text-sm text-ink-muted">{label}</span>
        <span className="ml-auto flex min-w-0 flex-1 justify-end">{children}</span>
      </label>
      {hint === undefined ? null : <p className={`px-3 pb-2 ${hintText}`}>{hint}</p>}
    </div>
  );
}

// The amber band. Amber is a notice and red destroys something; nothing else on
// a screen is coloured, so this is what draws the eye before it reads.
export function Notice({ children, tone = "notice" }: { children: ReactNode; tone?: "notice" | "danger" }) {
  const danger = tone === "danger";
  return (
    <p
      role={danger ? "alert" : "status"}
      className={
        danger
          ? "flex items-center gap-2 rounded-lg border border-control-line px-3 py-2 text-sm text-danger"
          : "flex items-center gap-2 rounded-lg border border-notice-line bg-notice px-3 py-2 text-sm text-notice-ink"
      }
    >
      {children}
    </p>
  );
}

type ButtonProps = { kind?: "primary" | "secondary" | "danger" } & ButtonHTMLAttributes<HTMLButtonElement>;

// type="button" by default because every button in this application is one:
// there is no form submission anywhere, and a button that defaulted to
// "submit" inside a <form> would reload the page and lose the session.
export function Button({ kind = "secondary", className = "", type = "button", ...rest }: ButtonProps) {
  const base = kind === "primary" ? primaryAction : kind === "danger" ? dangerAction : secondaryAction;
  return <button type={type} className={`${base} ${className}`} {...rest} />;
}
