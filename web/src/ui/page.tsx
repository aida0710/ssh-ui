import type { ReactNode } from "react";

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h2 className="text-xl font-semibold text-ink">{title}</h2>
        <p className="mt-1 max-w-3xl text-sm leading-6 text-ink-muted">{description}</p>
      </div>
      {actions === undefined ? null : <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>}
    </header>
  );
}

export function MetricCard({
  label,
  value,
  detail,
  attention = false,
}: {
  label: string;
  value: string | number;
  detail?: string;
  attention?: boolean;
}) {
  return (
    <div className={`rounded-xl border bg-card p-4 ${attention ? "border-notice-line" : "border-line"}`}>
      <p className={`text-xs font-medium uppercase tracking-wide ${attention ? "text-notice-ink" : "text-ink-muted"}`}>
        {label}
      </p>
      <p className="mt-1 text-2xl font-semibold text-ink">{value}</p>
      {detail === undefined ? null : <p className="mt-1 text-xs text-ink-muted">{detail}</p>}
    </div>
  );
}

export function MetricGrid({ children }: { children: ReactNode }) {
  return <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{children}</div>;
}
