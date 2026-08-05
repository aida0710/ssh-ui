import { useEffect, useState } from "react";
import { apiClient, type HealthResponse } from "./api/client";
import type { SessionState } from "./session/bootstrap";
import { ConnectionsPage } from "./connections/ConnectionsPage";
import { ConfigExplorer, type FileTarget } from "./explorer/ConfigExplorer";
import { GroupsPanel } from "./groups/GroupsPanel";
import { HistoryPanel } from "./history/HistoryPanel";
import { KeysScreen } from "./keys/KeysScreen";
import { DiagnosticsPanel } from "./diagnostics/DiagnosticsPanel";
import { KnownHostsPanel } from "./knownhosts/KnownHostsPanel";
import { RemoteKeyPanel } from "./remotekeys/RemoteKeyPanel";
import { LanguageProvider, useLanguage } from "./i18n/context";
import { locales, type Locale } from "./i18n/locale";
import type { MessageKey } from "./i18n/messages";

type AppProps = {
  bootstrap: () => Promise<SessionState>;
  health: () => Promise<HealthResponse>;
};

const sections = [
  "Connections",
  "Config",
  "Groups",
  "Keys",
  "Known Hosts",
  "Remote Keys",
  "Diagnostics",
  "History",
] as const;
type Section = (typeof sections)[number];
const enabledSections: Section[] = [...sections];

// The section identifiers stay English and untranslated: they are this
// component's own routing vocabulary, and translating them would make which
// panel is open depend on the display language.
const sectionLabels: Record<Section, MessageKey> = {
  Connections: "section.connections",
  Config: "section.config",
  Groups: "section.groups",
  Keys: "section.keys",
  "Known Hosts": "section.knownHosts",
  "Remote Keys": "section.remoteKeys",
  Diagnostics: "section.diagnostics",
  History: "section.history",
};

const localeLabels: Record<Locale, MessageKey> = {
  en: "shell.languageEnglish",
  ja: "shell.languageJapanese",
};

export function App({ bootstrap, health }: AppProps) {
  const { t, locale, setLocale } = useLanguage();
  const [state, setState] = useState<"starting" | "ready" | "error">("starting");
  const [version, setVersion] = useState("");
  const [section, setSection] = useState<Section>("Connections");
  const [fileTarget, setFileTarget] = useState<FileTarget | null>(null);

  // The shell owns section switching, so a view that can only address a block
  // by file and line hands the jump up here rather than routing by itself.
  function openFile(path: string, line: number) {
    setFileTarget({ path, line });
    setSection("Config");
  }

  useEffect(() => {
    let active = true;
    void bootstrap()
      .then((sessionState) => {
        if (!active) return null;
        apiClient.setCSRF(sessionState.csrfToken);
        return health();
      })
      .then((result) => {
        if (!active || result === null) return;
        setVersion(result.version);
        setState("ready");
      })
      .catch(() => {
        if (active) setState("error");
      });

    return () => {
      active = false;
      apiClient.clear();
    };
  }, [bootstrap, health]);

  if (state === "error") {
    return (
      <main>
        <h1>{t("shell.title")}</h1>
        <p role="alert">{t("shell.bootstrapFailed")}</p>
      </main>
    );
  }

  // The shell is exactly one viewport tall and never scrolls as a whole: the
  // header and the primary navigation stay put while a panel scrolls inside
  // main. A page-level scroll would carry the session status and the section
  // buttons off screen, which is wrong for a shell whose status line reports
  // whether the local session is still alive.
  //
  // min-h-0 on the body row is what makes that true. A flex child's default
  // min-height is its content, so without it a tall panel grows the row past
  // the viewport and the document scrolls again. grid-rows-[minmax(0,1fr)]
  // does the same for the implicit row, which would otherwise be sized by its
  // content rather than clamped to the row it was given.
  //
  // `relative` on the two scrolling regions is not decoration. The screen
  // reader descriptions the connection tree writes are `sr-only`, which is
  // `position: absolute`, and an absolutely positioned element is clipped by
  // an ancestor's overflow only when that ancestor is its containing block. A
  // static main is not, so those spans resolved against the initial containing
  // block, sat at their static offset far below the fold, and stretched the
  // document's scrolling area — the header scrolled away again while the panel
  // itself looked correctly clipped.
  return (
    <div className="flex h-screen flex-col bg-zinc-950 text-zinc-100">
      <header className="flex shrink-0 items-baseline gap-3 border-b border-zinc-800 px-6 py-4">
        <h1 className="text-xl font-semibold">{t("shell.title")}</h1>
        <p role="status" className="text-sm text-zinc-300">
          {state === "ready" ? t("shell.active", { version }) : t("shell.starting")}
        </p>
        <label htmlFor="language" className="ml-auto text-sm text-zinc-400">
          {t("shell.language")}
        </label>
        <select
          id="language"
          value={locale}
          onChange={(event) => setLocale(event.target.value as Locale)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        >
          {locales.map((candidate) => (
            <option key={candidate} value={candidate}>
              {t(localeLabels[candidate])}
            </option>
          ))}
        </select>
      </header>
      <div className="grid min-h-0 flex-1 grid-cols-[15rem_1fr] grid-rows-[minmax(0,1fr)]">
        <nav aria-label={t("shell.primaryNavigation")} className="relative overflow-y-auto border-r border-zinc-800 p-4">
          <ul>
            {sections.map((name) => (
              <li key={name}>
                <button
                  type="button"
                  disabled={!enabledSections.includes(name)}
                  aria-current={section === name ? "page" : undefined}
                  onClick={() => setSection(name)}
                  className={`w-full px-3 py-2 text-left ${
                    enabledSections.includes(name) ? "text-zinc-200 hover:bg-zinc-900" : "text-zinc-500"
                  }`}
                >
                  {t(sectionLabels[name])}
                </button>
              </li>
            ))}
          </ul>
        </nav>
        <main className="relative overflow-y-auto p-6">
          {state === "ready" ? (
            <SectionView section={section} fileTarget={fileTarget} onOpenFile={openFile} />
          ) : null}
        </main>
      </div>
    </div>
  );
}

type SectionViewProps = {
  section: Section;
  fileTarget: FileTarget | null;
  onOpenFile: (path: string, line: number) => void;
};

function SectionView({ section, fileTarget, onOpenFile }: SectionViewProps) {
  if (section === "Connections") {
    return <ConnectionsPage onOpenFile={onOpenFile} />;
  }
  if (section === "Config") {
    return <ConfigExplorer target={fileTarget} />;
  }
  if (section === "Groups") {
    return <GroupsPanel />;
  }
  if (section === "History") {
    return <HistoryPanel />;
  }
  if (section === "Keys") {
    return <KeysScreen />;
  }
  if (section === "Known Hosts") {
    return <KnownHostsPanel />;
  }
  if (section === "Remote Keys") {
    return <RemoteKeyPanel />;
  }
  if (section === "Diagnostics") {
    return <DiagnosticsPanel />;
  }
  return (
    <section aria-labelledby="section-heading" className="flex flex-col gap-4">
      <h2 id="section-heading" className="font-medium">{section}</h2>
    </section>
  );
}
