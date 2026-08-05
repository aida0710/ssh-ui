import type { ReactNode } from "react";

// The shared look of every form control.
//
// This exists because three panels had grown their own and one had none at all.
// On a dark background a bare <input> is not merely plain, it is invisible:
// black text on a black page with no border and no background. The Keys screen
// asked for a file name, a comment and a passphrase in three fields nobody
// could see. One definition here is what stops that happening again.
export const control =
  "w-full rounded border border-zinc-700 bg-zinc-900 px-2 py-1.5 text-sm text-zinc-100 " +
  "placeholder:text-zinc-500 focus:border-zinc-400 focus:outline-none " +
  "disabled:border-zinc-800 disabled:text-zinc-500";

// A control that should not stretch: a number, a colour, a short name.
export const narrowControl = control.replace("w-full", "w-40");

// A button label is a name, not a paragraph. Left to wrap, "Remove office"
// broke across two lines the moment its row ran out of room and the button grew
// a second storey. Wrapping the row is right; wrapping the word is not.
export const primaryAction =
  "whitespace-nowrap rounded bg-zinc-200 px-3 py-1.5 text-sm font-medium text-zinc-900 hover:bg-white " +
  "disabled:bg-zinc-700 disabled:text-zinc-500";

export const secondaryAction =
  "whitespace-nowrap rounded border border-zinc-700 px-3 py-1.5 text-sm hover:bg-zinc-800 disabled:text-zinc-600";

export const dangerAction =
  "whitespace-nowrap rounded border border-rose-700 px-3 py-1.5 text-sm text-rose-300 hover:bg-rose-950";

export const fieldLabel = "text-xs font-medium tracking-wide text-zinc-400";
export const hintText = "text-xs text-zinc-500";
export const sectionCard = "flex flex-col gap-4 rounded-xl border border-zinc-800 p-4";
export const sectionHeading = "text-sm font-medium text-zinc-100";

// Table cells had no padding at all, so a header sat against the value above
// it and the columns ran together.
export const tableHeadRow = "border-b border-zinc-700 text-xs uppercase tracking-wide text-zinc-400";
export const tableHeadCell = "py-2 pr-3 text-left font-medium";

type FieldProps = {
  label: string;
  hint?: string;
  children: ReactNode;
};

// Field pairs a caption with one control.
//
// The label element wraps the control rather than pointing at it by id, which
// is how every form in this application already associated the two, so the
// accessible name is unchanged and no test selector moves.
//
// The hint sits outside that label on purpose. Inside it, a whole sentence of
// advice became part of the control's accessible name, so a field captioned
// "New group name" announced itself as "New group name Use a slash to nest:
// work/eu is a group inside work."
export function Field({ label, hint, children }: FieldProps) {
  return (
    <div className="flex flex-col gap-1">
      <label className="flex flex-col gap-1">
        <span className={fieldLabel}>{label}</span>
        {children}
      </label>
      {hint === undefined ? null : <span className={hintText}>{hint}</span>}
    </div>
  );
}

type CheckboxFieldProps = {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
};

// CheckboxField puts the box beside its sentence with room to breathe, and
// aligns the two at the top so a wrapped sentence does not push the box down
// to its middle.
export function CheckboxField({ label, checked, onChange }: CheckboxFieldProps) {
  return (
    <label className="flex items-start gap-2 text-sm text-zinc-300">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="mt-0.5 h-4 w-4 shrink-0 accent-zinc-300"
      />
      <span>{label}</span>
    </label>
  );
}
