import { useEffect, useState, type ReactNode } from "react";
import { apiClient, whenLocked, type HealthResponse } from "./api/client";
import { integrationsApi, type PasswordVaultStatus } from "./api/integrations";
import { configApi } from "./api/config";
import type { SessionState } from "./session/bootstrap";
import { ConnectionsPage } from "./connections/ConnectionsPage";
import { ConfigExplorer, type FileTarget } from "./explorer/ConfigExplorer";
import { GroupsPanel } from "./groups/GroupsPanel";
import { HistoryPanel } from "./history/HistoryPanel";
import { KeysScreen } from "./keys/KeysScreen";
import { DiagnosticsPanel } from "./diagnostics/DiagnosticsPanel";
import { LockScreen } from "./secrets/LockScreen";
import { UpdateBadge } from "./shell/UpdateBadge";
import { SecretsPanel } from "./secrets/SecretsPanel";
import { SyncPanel } from "./sync/SyncPanel";
import { KnownHostsPanel } from "./knownhosts/KnownHostsPanel";
import { RemoteKeyPanel } from "./remotekeys/RemoteKeyPanel";
import { LanguageProvider, useLanguage } from "./i18n/context";
import { locales, type Locale } from "./i18n/locale";
import { control } from "./ui/form";
import { Icon, IconSprite, type IconName } from "./ui/icons";
import { InspectorPane, InspectorToggle, type InspectorContent } from "./ui/Inspector";
import { useTheme } from "./theme/context";
import { themes, type Theme } from "./theme/theme";
import type { MessageKey } from "./i18n/messages";

type AppProps = {
  bootstrap: () => Promise<SessionState>;
  health: () => Promise<HealthResponse>;
  // vault answers whether the application is open. It is injected for the same
  // reason bootstrap and health are: the shell's own state machine is what the
  // tests drive, not the transport under it.
  vault?: () => Promise<PasswordVaultStatus>;
};

const sections = [
  "Connections",
  "Config",
  "Groups",
  "Keys",
  "Known Hosts",
  "Remote Keys",
  "Diagnostics",
  "Secrets",
  "Sync",
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
  Secrets: "section.secrets",
  Sync: "section.sync",
  History: "section.history",
};

const localeLabels: Record<Locale, MessageKey> = {
  en: "shell.languageEnglish",
  ja: "shell.languageJapanese",
};

const sectionIcons: Record<Section, IconName> = {
  Connections: "connections",
  Config: "config",
  Groups: "groups",
  Keys: "keys",
  "Known Hosts": "knownHosts",
  "Remote Keys": "remoteKeys",
  Diagnostics: "diagnostics",
  Secrets: "secrets",
  Sync: "sync",
  History: "history",
};

// Ten sections listed flat give no clue which are near each other.
//
// The group label is an `aria-label` on the list and an `aria-hidden` span for
// the eye — deliberately not a heading. Playwright matches accessible names by
// substring, so a heading "Keys and hosts" would make the end-to-end suite's
// page-level query for the heading "Keys" match twice and fail on strict mode.
const navGroups: { label: MessageKey; sections: Section[] }[] = [
  { label: "shell.navConnections", sections: ["Connections", "Config", "Groups"] },
  { label: "shell.navKeysHosts", sections: ["Keys", "Known Hosts", "Remote Keys"] },
  { label: "shell.navMaintenance", sections: ["Diagnostics", "Secrets", "Sync", "History"] },
];

const themeLabels: Record<Theme, MessageKey> = {
  system: "shell.themeSystem",
  light: "shell.themeLight",
  dark: "shell.themeDark",
};

export function App({ bootstrap, health, vault = integrationsApi.passwordVault }: AppProps) {
  const { t, locale, setLocale } = useLanguage();
  const { theme, setTheme } = useTheme();
  // "locked" is the whole application, not a screen inside it. Every write
  // keeps a backup sealed with the master password, so there is no usable state
  // in which the vault is shut.
  const [state, setState] = useState<"starting" | "locked" | "ready" | "error">("starting");
  const [vaultExists, setVaultExists] = useState(false);
  const [version, setVersion] = useState("");
  const [section, setSection] = useState<Section>("Connections");
  const [fileTarget, setFileTarget] = useState<FileTarget | null>(null);
  // The declared group names, read once the session is up. The Keys screen
  // offers them as destinations; it never infers a group from a directory,
  // because a directory is a group only when the entry file declares it.
  const [groups, setGroups] = useState<string[]>([]);
  // The pane belongs to the shell, not to a section. Opened on Connections it
  // is still open on Keys: a pane that shut itself on every section change
  // would have to be reopened constantly, and this is a preference about the
  // window rather than about a host.
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [inspector, setInspector] = useState<InspectorContent>(null);
  // What the open section puts in the toolbar. The shell owns the strip; the
  // section says what belongs in it.
  const [toolbar, setToolbar] = useState<ReactNode>(null);

  // The pane's contents belong to whichever section is open; its open state
  // does not. Leaving a section therefore clears what is in the pane without
  // closing it. The toolbar's contents go the same way, and have no state to
  // keep.
  useEffect(() => {
    setInspector(null);
    setToolbar(null);
  }, [section]);

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
        if (!active || result === null) return null;
        setVersion(result.version);
        return vault();
      })
      .then((status) => {
        if (!active || status === null) return;
        setVaultExists(status.exists);
        if (!status.unlocked) {
          setState("locked");
          return;
        }
        setState("ready");
      })
      .catch(() => {
        if (active) setState("error");
      });

    return () => {
      active = false;
      apiClient.clear();
    };
  }, [bootstrap, health, vault]);

  // The vault shuts itself after a day of not being used, which can happen
  // between any two requests. The client reports it once, here, so the shell
  // goes back to its front door instead of every screen reporting a failure on
  // an application that is no longer usable.
  useEffect(() => {
    whenLocked(() => {
      setVaultExists(true);
      setState("locked");
    });
    return () => whenLocked(null);
  }, []);

  // The declared groups are read once the application is open, not while it is
  // shut: every route that could answer refuses until then.
  useEffect(() => {
    if (state !== "ready") return;
    let active = true;
    void configApi
      .overview()
      .then((overview) => {
        if (active) setGroups((overview.metadata.groups ?? []).map((group) => group.name));
      })
      // A shell that cannot list groups still works: the destination list is
      // empty and every other screen is unaffected.
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [state]);

  if (state === "locked") {
    return <LockScreen exists={vaultExists} onOpen={() => setState("ready")} />;
  }

  if (state === "error") {
    return (
      <main className="p-6">
        <h1 className="text-base font-semibold">{t("shell.title")}</h1>
        <p role="alert" className="mt-2 text-sm text-danger">{t("shell.bootstrapFailed")}</p>
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
  //
  // The navigation is three lists rather than one. Their group labels are
  // `aria-label`s and `aria-hidden` spans, never headings: Playwright matches
  // accessible names by substring, so a heading "Keys and hosts" would make the
  // end-to-end suite's page-level query for the level-2 heading "Keys" match
  // twice and fail on a strict-mode violation.
  return (
    <div className="flex h-screen flex-col bg-canvas text-ink">
      <IconSprite />
      <header className="flex shrink-0 items-center gap-3 border-b border-line bg-toolbar px-6 py-2.5">
        {/*
          The application's name stays the h1 and the open section is shown
          beside it without being a heading. Making the section a heading would
          put "Known Hosts" and "Remote Keys" into the heading namespace twice —
          once here and once on the panel — and Playwright matches accessible
          names by substring, so the suite's page-level queries for those
          headings would find two elements and fail.
        */}
        <h1 className="text-xs font-medium text-ink-muted">{t("shell.title")}</h1>
        <span aria-hidden="true" className="text-xs text-ink-faint">/</span>
        <p className="text-sm font-semibold">{t(sectionLabels[section])}</p>
        <p role="status" className="flex items-center gap-1.5 text-xs text-ink-muted">
          <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-live" />
          {state === "ready" ? t("shell.active", { version }) : t("shell.starting")}
        </p>
        {toolbar === null ? null : <span className="ms-4">{toolbar}</span>}
        {inspector === null ? (
          <span className="ml-auto" />
        ) : (
          <span className="ml-auto">
            <InspectorToggle
              open={inspectorOpen}
              attention={inspector.attention}
              onToggle={() => setInspectorOpen((open) => !open)}
            />
          </span>
        )}
        <label htmlFor="appearance" className="text-sm text-ink-muted">
          {t("shell.theme")}
        </label>
        <select
          id="appearance"
          value={theme}
          onChange={(event) => setTheme(event.target.value as Theme)}
          className={control}
        >
          {themes.map((candidate) => (
            <option key={candidate} value={candidate}>
              {t(themeLabels[candidate])}
            </option>
          ))}
        </select>
        <label htmlFor="language" className="text-sm text-ink-muted">
          {t("shell.language")}
        </label>
        <select
          id="language"
          value={locale}
          onChange={(event) => setLocale(event.target.value as Locale)}
          className={control}
        >
          {locales.map((candidate) => (
            <option key={candidate} value={candidate}>
              {t(localeLabels[candidate])}
            </option>
          ))}
        </select>
      </header>
      <div
        className={`grid min-h-0 flex-1 grid-rows-[minmax(0,1fr)] ${
          // minmax(0,…) on the middle track for the same reason min-h-0 is on
          // the row: a bare 1fr is minmax(auto,1fr), so the column refuses to
          // shrink below its content and the panel runs out under the
          // inspector instead of narrowing to make room for it.
          inspector !== null && inspectorOpen
            ? "grid-cols-[15rem_minmax(0,1fr)_17rem]"
            : "grid-cols-[15rem_minmax(0,1fr)]"
        }`}
      >
        <nav
          aria-label={t("shell.primaryNavigation")}
          className="relative flex flex-col overflow-y-auto border-r border-line bg-sidebar p-2"
        >
          <div className="grow">
          {navGroups.map((group) => (
            <div key={group.label} className="mb-2">
              <span aria-hidden="true" className="block px-2 pt-2 pb-1 text-xs font-semibold text-ink-muted">
                {t(group.label)}
              </span>
              <ul aria-label={t(group.label)}>
                {group.sections.map((name) => (
                  <li key={name}>
                    <button
                      type="button"
                      disabled={!enabledSections.includes(name)}
                      aria-current={section === name ? "page" : undefined}
                      onClick={() => setSection(name)}
                      className={`flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm ${
                        section === name
                          ? "bg-select-fill text-ink"
                          : enabledSections.includes(name)
                            ? "text-ink hover:bg-select-fill"
                            : "text-ink-faint"
                      }`}
                    >
                      <Icon name={sectionIcons[name]} className="h-4 w-4 text-ink-muted" />
                      {t(sectionLabels[name])}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
          </div>
          {/*
            The version sits at the foot of the navigation, where a thing you
            look at rarely belongs, with the one control that changes it.
          */}
          <UpdateBadge />
        </nav>
        {/*
          No padding here. A section that wants to fill the window edge to edge
          — Connections, whose list is a surface of its own — cannot do that
          inside a padded box, so the padding is the section's to apply and
          SectionView applies it for the nine that want it.
        */}
        <main className="relative overflow-hidden">
          {state === "ready" ? (
            <SectionView
              section={section}
              fileTarget={fileTarget}
              groups={groups}
              onOpenFile={openFile}
              onLock={() => setState("locked")}
              onInspector={setInspector}
              onToolbar={setToolbar}
            />
          ) : null}
        </main>
        {inspector !== null && inspectorOpen ? (
          <InspectorPane label={t("shell.inspector")}>{inspector.body}</InspectorPane>
        ) : null}
      </div>
    </div>
  );
}

type SectionViewProps = {
  // groups are the declared group names. The Keys screen needs them to offer a
  // destination, and it must not infer them: a directory is a group because a
  // line in ~/.ssh/config declares it, which only the configuration API reads.
  groups: string[];
  section: Section;
  fileTarget: FileTarget | null;
  onOpenFile: (path: string, line: number) => void;
  onLock: () => void;
  // A section supplies the right-hand pane's contents, or null when it has
  // nothing to inspect. Only Connections fills it today.
  onInspector: (content: InspectorContent) => void;
  // What this section puts in the toolbar, or nothing.
  onToolbar: (content: ReactNode) => void;
};

function SectionView(props: SectionViewProps) {
  // Connections lays out its own panes to the window's edges. Every other
  // section is a document, and a document wants a margin and a scrollbar.
  if (props.section === "Connections") {
    return (
      <ConnectionsPage
        onOpenFile={props.onOpenFile}
        onInspector={props.onInspector}
        onToolbar={props.onToolbar}
      />
    );
  }
  return <div className="h-full overflow-y-auto p-6">{<PaddedSection {...props} />}</div>;
}

function PaddedSection({ section, fileTarget, groups, onOpenFile, onLock, onInspector }: SectionViewProps) {
  if (section === "Config") {
    return <ConfigExplorer target={fileTarget} />;
  }
  if (section === "Groups") {
    return <GroupsPanel onInspector={onInspector} />;
  }
  if (section === "Secrets") {
    return <SecretsPanel onLock={onLock} />;
  }
  if (section === "Sync") {
    return <SyncPanel />;
  }
  if (section === "History") {
    return <HistoryPanel />;
  }
  if (section === "Keys") {
    return <KeysScreen groups={groups} />;
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
