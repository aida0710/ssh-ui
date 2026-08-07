import { useEffect, useState } from "react";
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
import { useLanguage } from "./i18n/context";
import { locales, type Locale } from "./i18n/locale";
import { autoControl } from "./ui/form";
import { Icon, IconSprite, type IconName } from "./ui/icons";
import { InspectorPane, InspectorToggle, type InspectorContent } from "./ui/Inspector";
import { useTheme } from "./theme/context";
import { themes, type Theme } from "./theme/theme";
import type { MessageKey } from "./i18n/messages";

type AppProps = {
  bootstrap: () => Promise<SessionState>;
  health: () => Promise<HealthResponse>;
  // vault はアプリケーションが開いているかどうかを答える。bootstrap や health と
  // 同じ理由でここに注入されている——テストが動かすのはシェル自身の状態機械で
  // あって、その下のトランスポートではないからだ。
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

// セクション識別子は英語のまま訳さない。これはこのコンポーネント自身の
// ルーティング語彙であり、訳してしまうとどのパネルが開いているかが表示
// 言語に依存することになってしまう。
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

// 十個のセクションを平たく並べただけでは、どれとどれが近いのか手がかりがない。
//
// グループラベルはリストに付けた `aria-label` と、目のための `aria-hidden`
// span である——意図的に見出しにはしていない。Playwright はアクセシブル
// ネームを部分一致で照合するため、見出しを "Keys and hosts" にすると、end-to-end
// スイートの "Keys" へのページレベルクエリが二重に一致し、strict モードで失敗する。
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
  // "locked" はアプリケーション全体を指し、その中の一画面ではない。あらゆる
  // 書き込みはマスターパスワードで封じたバックアップを残すため、vault が
  // 閉じたまま使える状態というものは存在しない。
  const [state, setState] = useState<"starting" | "locked" | "ready" | "error">("starting");
  const [vaultExists, setVaultExists] = useState(false);
  const [version, setVersion] = useState("");
  const [section, setSection] = useState<Section>("Connections");
  const [fileTarget, setFileTarget] = useState<FileTarget | null>(null);
  // 宣言済みのグループ名は、セッションが立ち上がった時点で一度だけ読む。
  // Keys 画面は移動先としてそれらを提示するだけで、ディレクトリからグルー
  // プを推測しない。ディレクトリがグループになるのはエントリファイルが宣言する場合だけだ。
  const [groups, setGroups] = useState<string[]>([]);
  // ペインはシェルに属するものであり、セクションに属するものではない。
  // Connections で開いたものは Keys でも開いたままになる——セクションを
  // 切り替えるたびに自分で閉じるペインでは、頻繁に開き直す羽目になる。
  // これはホストについての好みではなく、ウィンドウについての好みだからだ。
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [inspector, setInspector] = useState<InspectorContent>(null);

  // ペインの中身はどのセクションが開いているかに属するが、開閉状態自体は
  // そうではない。したがってセクションを離れるとペインの中身は消去され
  // るが、ペイン自体が閉じられることはない。
  //
  // ヘッダーにはセクションが埋められるスロットはもう無い。かつては
  // Connections ツリーの並び替えコントロール用のスロットがあり、ここ
  // でクリアする実装のせいで、他の画面に移った瞬間にそのコントロールが消えてしまっていた。
  // 一つのリストに属するコントロールは、今はそのリストの中にある。
  useEffect(() => {
    setInspector(null);
  }, [section]);

  // セクション切り替えはシェルが所有するので、ブロックをファイルと行でし
  // か指し示せないビューは、自分でルーティングせずジャンプをここに委ねる。
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

  // vault は一日使われないと自動的に閉じ、それはどの二つのリクエストの
  // 間にも起こり得る。クライアントはそれをここで一度だけ報告し、シェル
  // を入口へ戻す。そうしないと、もう使えなくなったアプリケーションに対
  // して、あらゆる画面が個別に失敗を報告することになってしまう。
  useEffect(() => {
    whenLocked(() => {
      setVaultExists(true);
      setState("locked");
    });
    return () => whenLocked(null);
  }, []);

  // 宣言済みグループはアプリケーションが開いている間に一度だけ読み込ま
  // れる。閉じている間は読まない——応答できるはずのルートも、それまでは拒否する。
  useEffect(() => {
    if (state !== "ready") return;
    let active = true;
    void configApi
      .overview()
      .then((overview) => {
        if (active) setGroups((overview.metadata.groups ?? []).map((group) => group.name));
      })
      // グループを列挙できないシェルでも動作は成立する——移動先リストが
      // 空になるだけで、他のあらゆる画面には影響しない。
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

  // シェルの高さはちょうどビューポート一つ分で、全体としてスクロール
  // することはない。ヘッダーと主要なナビゲーションは固定され、main の
  // 中でパネルだけがスクロールする。ページ全体がスクロールしてしまうと
  // セッション状態とセクションボタンが画面外に流れてしまい、ローカル
  // セッションがまだ生きているかを報告するステータス行を持つシェルとしては、それは誤りだ。
  //
  // それを実現しているのが body 行の min-h-0 だ。flex の子要素の
  // min-height は既定でコンテンツサイズになるため、これが無いと丈の高い
  // パネルが行をビューポートより押し広げ、ドキュメントが再びスクロール
  // してしまう。grid-rows-[minmax(0,1fr)] は暗黙の行に対して同じ役割を
  // 果たす——無ければその行は与えられた枠に収まらず、コンテンツのサイズで決まってしまう。
  //
  // 二つのスクロール領域に付けた `relative` は装飾ではない。connection
  // tree が書き出すスクリーンリーダー用の説明は `sr-only` であり、これは
  // `position: absolute` を意味する。絶対配置の要素が祖先の overflow で
  // クリップされるのは、その祖先が containing block である場合に限られる。
  // static な main はそうではないため、それらの span は初期 containing
  // block を基準に解決され、fold のはるか下の static な位置に置かれて、
  // ドキュメントのスクロール領域を引き伸ばしていた——パネル自体は正しく
  // クリップされて見える一方で、ヘッダーはまた画面外へ流れてしまっていた。
  //
  // ナビゲーションは一つではなく三つのリストである。それぞれのグループ
  // ラベルは `aria-label` と `aria-hidden` span であり、見出しには決して
  // しない。Playwright はアクセシブルネームを部分一致で照合するため、見
  // 出しを "Keys and hosts" にすると、end-to-end スイートの見出しレベル
  // 2 の "Keys" へのページレベルクエリが二重に一致し、strict モード違反で失敗する。
  return (
    <div className="flex h-screen flex-col bg-canvas text-ink">
      <IconSprite />
      <header className="flex shrink-0 items-center gap-3 border-b border-line bg-toolbar px-6 py-2.5">
        {/*
          アプリケーション名は引き続き h1 であり、開いているセクションは
          見出しにせずその横に表示する。セクションを見出しにしてしまうと
          "Known Hosts" と "Remote Keys" が見出し名前空間に二重に入る——
          ここで一回、パネルでもう一回——Playwright はアクセシブル
          ネームを部分一致で照合するため、スイートのページレベルクエリは
          それらの見出しを二つ見つけてしまい、失敗する。
        */}
        <h1 className="shrink-0 whitespace-nowrap text-xs font-medium text-ink-muted">{t("shell.title")}</h1>
        <span aria-hidden="true" className="text-xs text-ink-faint">/</span>
        <p className="shrink-0 whitespace-nowrap text-sm font-semibold">{t(sectionLabels[section])}</p>
        <p role="status" className="flex min-w-0 items-center gap-1.5 truncate text-xs text-ink-muted">
          <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-live" />
          {state === "ready" ? t("shell.active", { version }) : t("shell.starting")}
        </p>
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
        <label htmlFor="appearance" className="shrink-0 whitespace-nowrap text-sm text-ink-muted">
          {t("shell.theme")}
        </label>
        <select
          id="appearance"
          value={theme}
          onChange={(event) => setTheme(event.target.value as Theme)}
          className={autoControl}
        >
          {themes.map((candidate) => (
            <option key={candidate} value={candidate}>
              {t(themeLabels[candidate])}
            </option>
          ))}
        </select>
        <label htmlFor="language" className="shrink-0 whitespace-nowrap text-sm text-ink-muted">
          {t("shell.language")}
        </label>
        <select
          id="language"
          value={locale}
          onChange={(event) => setLocale(event.target.value as Locale)}
          className={autoControl}
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
            バージョンはナビゲーションの最下部に置く。めったに見ない
            ものが置かれる場所であり、それを変える唯一のコントロールと共に。
          */}
          <UpdateBadge />
        </nav>
        {/*
          ここに padding は無い。ウィンドウの端から端まで埋めたいセクション
          ——それ自身が一つの面である Connections のリスト——は、padding
          の付いた箱の中ではそれができない。だから padding を適用するのは
          セクション側の役目であり、SectionView がそれを望む九画面に適用している。
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
  // groups は宣言済みのグループ名である。Keys 画面はこれを移動先とし
  // て提示する必要があるが、推測してはならない——ディレクトリがグルー
  // プなのは ~/.ssh/config の一行が宣言するからで、読むのは configuration API だけだ。
  groups: string[];
  section: Section;
  fileTarget: FileTarget | null;
  onOpenFile: (path: string, line: number) => void;
  onLock: () => void;
  // セクションは右側ペインの中身を提供するか、調べるものが無ければ
  // null を返す。現時点でそれを埋めているのは Connections だけだ。
  onInspector: (content: InspectorContent) => void;
};

function SectionView(props: SectionViewProps) {
  // Connections は自前のペインをウィンドウの端まで配置する。それ以外の
  // セクションはすべて文書であり、文書には余白とスクロールバーが要る。
  if (props.section === "Connections") {
    return (
      <ConnectionsPage
        onOpenFile={props.onOpenFile}
        onInspector={props.onInspector}
      />
    );
  }
  return <div className="h-full overflow-y-auto p-6">{<PaddedSection {...props} />}</div>;
}

function PaddedSection({ section, fileTarget, groups, onLock, onInspector }: SectionViewProps) {
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
