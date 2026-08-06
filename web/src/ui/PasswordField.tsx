import { useState, type ReactNode } from "react";
import { useTranslate } from "../i18n/context";
import { Field, control } from "./form";

type PasswordFieldProps = {
  label: string;
  value: string;
  onChange: (value: string) => void;
  hint?: string;
  autoFocus?: boolean;
};

// A password field that can be read back.
//
// Every password this application asks for is one the user cannot recover if
// they mistype it — the master password most of all — and a field that never
// shows what is in it makes a typo something you find out about later, from a
// refusal that does not say which character was wrong. The toggle is per field,
// so revealing one does not reveal the one beside it.
//
// The button sits outside the label on purpose. A label wraps its control to
// associate the two, and every other word inside it becomes part of that
// control's accessible name: with the toggle in there, the field announced
// itself as "Master password Show" and nothing looking for it by name found it.
export function PasswordField({ label, value, onChange, hint, autoFocus }: PasswordFieldProps): ReactNode {
  const t = useTranslate();
  const [shown, setShown] = useState(false);
  return (
    <div className="flex items-end gap-2">
      <div className="grow">
        <Field label={label} {...(hint === undefined ? {} : { hint })}>
          <input
            type={shown ? "text" : "password"}
            value={value}
            autoFocus={autoFocus ?? false}
            onChange={(event) => onChange(event.target.value)}
            className={control}
          />
        </Field>
      </div>
      {/*
        Named after the field it reveals, so a screen with three of them has
        three distinguishable buttons rather than three called "Show".
      */}
      <button
        type="button"
        onClick={() => setShown(!shown)}
        aria-pressed={shown}
        aria-label={t(shown ? "password.hideNamed" : "password.showNamed", { label })}
        className="whitespace-nowrap rounded border border-control-line px-2 py-1.5 text-xs text-ink-muted hover:bg-select-fill"
      >
        {shown ? t("password.hide") : t("password.show")}
      </button>
    </div>
  );
}
