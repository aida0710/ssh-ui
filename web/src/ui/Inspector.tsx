import type { ReactNode } from "react";
import { Icon } from "./icons";
import { useTranslate } from "../i18n/context";

// What a section puts in the right-hand pane, and whether what is in there
// needs attention. A section that supplies null gets no toggle at all: a pane
// offered everywhere and empty in nine places out of ten teaches people not to
// open it.
export type InspectorContent = { attention: boolean; body: ReactNode } | null;

export const inspectorId = "inspector";

export function InspectorToggle({
  open,
  attention,
  onToggle,
}: {
  open: boolean;
  attention: boolean;
  onToggle: () => void;
}) {
  const t = useTranslate();
  const action = t(open ? "shell.inspectorHide" : "shell.inspectorShow");
  // The name is written here rather than assembled from two sr-only spans.
  // Adjacent spans concatenate without a separator — "Show detailsNeeds
  // attention" — because the only thing between them is an aria-hidden icon and
  // JSX strips the whitespace around it.
  const name = attention ? `${action} ${t("shell.inspectorAttention")}` : action;
  return (
    <button
      type="button"
      aria-label={name}
      aria-expanded={open}
      aria-controls={inspectorId}
      onClick={onToggle}
      className={`relative rounded-md border border-control-line px-2 py-1 text-ink ${
        open ? "bg-select-fill" : "bg-card"
      }`}
    >
      <Icon name="inspector" className="h-4 w-4" />
      {/* The dot is for the eye; the sentence above is for everyone else. */}
      {attention ? (
        <span
          aria-hidden="true"
          className="absolute -right-1 -top-1 h-2 w-2 rounded-full border border-toolbar bg-notice-ink"
        />
      ) : null}
    </button>
  );
}

export function InspectorPane({ label, children }: { label: string; children: ReactNode }) {
  return (
    <aside
      id={inspectorId}
      aria-label={label}
      className="relative overflow-y-auto border-l border-line bg-sidebar p-3"
    >
      {children}
    </aside>
  );
}
