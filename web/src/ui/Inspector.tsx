import type { ReactNode } from "react";
import { Icon } from "./icons";
import { useTranslate } from "../i18n/context";

// セクションが右側のペインに何を置くか、そしてそこにあるものが
// 注意を必要とするかどうか。null を渡すセクションにはトグルすら付かない:
// どこにでも提供されるのに 10 回のうち 9 回は空のペインは、人々にそれを
// 開かないよう教え込んでしまう。
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
  // 名前は 2 つの sr-only span から組み立てるのではなく、ここに直接書く。
  // 隣接する span はセパレータなしで連結され——「Show detailsNeeds
  // attention」——になる。両者の間にあるのは aria-hidden なアイコンだけで、
  // JSX がその周りの空白を取り除いてしまうからだ。
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
      {/* ドットは目のためのもので、上の文はそれ以外のすべての人のためのものだ。 */}
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
