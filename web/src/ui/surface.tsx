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
export function Row({
  label,
  children,
  hint,
  warning,
  action,
}: {
  label: string;
  children: ReactNode;
  // `| undefined` is written out because this project sets
  // exactOptionalPropertyTypes: without it a caller cannot compute "no hint"
  // and pass the result, only omit the attribute entirely.
  hint?: string | undefined;
  // Amber, and announced. A hint is advice; a warning is the engine reporting
  // something about this line.
  warning?: string | undefined;
  // A trailing control — "Remove", and its like.
  //
  // It is deliberately outside the label element. Inside it, clicking the
  // button would also activate the label and move focus into the field, and
  // the button's own word would join the field's accessible name.
  action?: ReactNode;
}) {
  return (
    <div className="border-t border-hairline first:border-t-0">
      <div className="flex items-center gap-3 px-3 py-2">
        <label className="flex min-w-0 flex-1 items-center gap-3">
          <span className="w-32 shrink-0 text-sm text-ink-muted">{label}</span>
          <span className="ml-auto flex min-w-0 flex-1 justify-end">{children}</span>
        </label>
        {action === undefined ? null : <span className="shrink-0">{action}</span>}
      </div>
      {hint === undefined ? null : <p className={`px-3 pb-2 ${hintText}`}>{hint}</p>}
      {warning === undefined ? null : (
        <p role="status" className="px-3 pb-2 text-xs text-notice-ink">
          {warning}
        </p>
      )}
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

// A segmented control: two or three exclusive choices, shown as one control
// rather than as separate buttons.
//
// The pressed state is `aria-pressed` on each segment rather than a radio
// group, which is what this application already used for the same control and
// what its tests address.
export function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
}) {
  return (
    <div role="group" aria-label={label} className="flex gap-0.5 rounded-md bg-select-fill p-0.5">
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={value === option.value}
          onClick={() => onChange(option.value)}
          className={`rounded px-2.5 py-0.5 text-xs ${
            value === option.value ? "bg-card text-ink shadow-sm" : "text-ink-muted"
          }`}
        >
          {option.label}
        </button>
      ))}
    </div>
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
