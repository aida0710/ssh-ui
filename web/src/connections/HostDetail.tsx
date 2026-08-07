import { useEffect, useMemo, useState } from "react";
import type { FieldEdit, FormField, GroupMetadata, HostDetail, SavePreview } from "../api/config";
import type { Problem } from "../api/client";
import { integrationsApi, type IntegrationsApi } from "../api/integrations";
import { DiagnosticsPanel } from "../diagnostics/DiagnosticsPanel";
import { PasswordPanel } from "../diagnostics/PasswordPanel";
import { formatValues, parseValues } from "./values";
import { NoticeList, SavePreviewPanel } from "./SavePreview";
import { useTranslate } from "../i18n/context";
import {
  control,
  fieldLabel,
  hintText,
  narrowControl,
  primaryAction,
  secondaryAction,
  sectionHeading,
} from "../ui/form";
import { Button, Card, Notice, Row } from "../ui/surface";
import type { MessageKey } from "../i18n/messages";

const tabs = ["Basic", "Jump", "Advanced", "Raw", "Effective", "Diagnostics"] as const;

// タブの識別子は英語のまま翻訳しない。下のフィールドカテゴリとレンダリング
// スイッチのキーになっているため、翻訳すればどのタブが開いているかが
// 表示言語に依存してしまう。
const tabLabels: Record<(typeof tabs)[number], MessageKey> = {
  Basic: "host.tabBasic",
  Jump: "host.tabJump",
  Advanced: "host.tabAdvanced",
  Raw: "host.tabRaw",
  Effective: "host.tabEffective",
  Diagnostics: "host.tabDiagnostics",
};
type Tab = (typeof tabs)[number];

const categoryForTab: Record<string, string> = { Basic: "basic", Jump: "jump", Advanced: "advanced" };

type HostDetailPanelProps = {
  detail: HostDetail;
  groups: GroupMetadata[];
  preview: SavePreview | null;
  problem: Problem | null;
  onFieldEdits: (edits: FieldEdit[]) => void;
  onBlockRaw: (raw: string) => void;
  onRename: (newAlias: string) => void;
  onComment: (comment: string) => void;
  // onMoveToGroup はフィールドを編集するのではなくファイルを移動する。グループは
  // ディレクトリであるため、それを変えることは移動であり、呼び出し側は
  // グループ名をサーバーへ送り、サーバーがそこから宛先パスを導出する。
  onMoveToGroup: (group: string) => void;
  // Diagnostics タブは Diagnostics section と同じ検査を行うため、
  // 同じクライアントを使う。これがプロパティであるのはテストが注入できるように
  // するためだけであり、ない場合パネルは実物のクライアントへフォールバックする。
  integrations?: IntegrationsApi;
};

function fieldKey(field: FormField): string {
  return `${field.line}-${field.keyword}`;
}

export function HostDetailPanel({
  detail,
  groups,
  preview,
  problem,
  onFieldEdits,
  onBlockRaw,
  onRename,
  onComment,
  onMoveToGroup,
  integrations = integrationsApi,
}: HostDetailPanelProps) {
  const t = useTranslate();
  const [tab, setTab] = useState<Tab>("Basic");
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [removed, setRemoved] = useState<number[]>([]);
  const [additions, setAdditions] = useState<FieldEdit[]>([]);
  const [newKeyword, setNewKeyword] = useState("");
  const [newValue, setNewValue] = useState("");
  const [blockRaw, setBlockRaw] = useState(detail.form.raw);
  const [renameTo, setRenameTo] = useState(detail.form.entry.identity.alias);
  // ファイルが実際にあるグループから始まる。これは射影がパスから
  // 読み取ったものであり、コントロールはそれを移動する前に、接続が
  // どこにあるかを示す。
  const [moveTo, setMoveTo] = useState(detail.form.entry.group ?? "");
  // レガシーの note は、ブロックにまだ comment がないときエディタの初期値になる。
  // 最初の save がそれを設定へ移し、両者が食い違ったままに
  // ならないようにする。書き込まれた後は、comment が唯一の由来である。
  const [comment, setComment] = useState(detail.form.comment || detail.metadata.note || "");
  const [localError, setLocalError] = useState("");

  // 別のホストを開く、あるいは save の後に同じホストを再読み込みすると、
  // すべての draft を破棄する。draft はそれを生んだブロックに対してのみ
  // 意味を持つ行番号を記述しているからである。
  const identityPath = detail.form.entry.identity.path;
  const identityAlias = detail.form.entry.identity.alias;
  const formRaw = detail.form.raw;
  useEffect(() => {
    setDrafts({});
    setRemoved([]);
    setAdditions([]);
    setNewKeyword("");
    setNewValue("");
    setBlockRaw(formRaw);
    setRenameTo(identityAlias);
    setComment(detail.form.comment || detail.metadata.note || "");
    setLocalError("");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [identityPath, identityAlias, formRaw]);

  const visibleFields = useMemo(
    () => detail.form.fields.filter((field) => field.category === categoryForTab[tab]),
    [detail.form.fields, tab],
  );

  function draftFor(field: FormField): string {
    return drafts[fieldKey(field)] ?? formatValues(field.values);
  }

  function submitFieldEdits() {
    const edits: FieldEdit[] = [];
    try {
      for (const field of detail.form.fields) {
        if (removed.includes(field.line)) {
          edits.push({ action: "remove", line: field.line });
          continue;
        }
        const draft = drafts[fieldKey(field)];
        if (draft === undefined) continue;
        edits.push({ action: "set", line: field.line, values: parseValues(draft) });
      }
      edits.push(...additions);
    } catch {
      setLocalError(t("host.unbalancedQuote"));
      return;
    }
    if (edits.length === 0) {
      setLocalError(t("host.nothingChanged"));
      return;
    }
    setLocalError("");
    onFieldEdits(edits);
  }

  function addDirective() {
    if (newKeyword === "") {
      setLocalError(t("host.needsKeyword"));
      return;
    }
    try {
      setAdditions([...additions, { action: "add", keyword: newKeyword, values: parseValues(newValue) }]);
    } catch {
      setLocalError(t("host.unbalancedQuote"));
      return;
    }
    setNewKeyword("");
    setNewValue("");
    setLocalError("");
  }

  return (
    <section className="flex flex-col gap-4">
      <header className="flex flex-col gap-1">
        <h2 className="text-lg font-medium">{detail.form.entry.identity.alias || detail.form.entry.patterns.join(" ")}</h2>
        <p className="text-xs text-ink-muted">
          {`${detail.form.entry.file.path ?? detail.form.entry.file.absolute}:${detail.form.entry.line}`}
        </p>
        <NoticeList notices={detail.form.notices ?? []} />
      </header>

      <div role="tablist" aria-label={t("host.editorLabel")} className="flex gap-1 border-b border-line">
        {tabs.map((name) => (
          <button
            key={name}
            type="button"
            role="tab"
            aria-selected={tab === name}
            onClick={() => setTab(name)}
            className={`px-3 py-2 text-sm ${tab === name ? "border-b-2 border-ink text-ink" : "text-ink-muted"}`}
          >
            {t(tabLabels[name])}
          </button>
        ))}
      </div>

      {localError === "" ? null : <Notice tone="danger">{localError}</Notice>}

      {tab === "Basic" || tab === "Jump" || tab === "Advanced" ? (
        <div className="flex flex-col gap-3">
          {/*
            一つのディレクティブに一つの行。keyword を左に、value を右に、
            その間にヘアライン、グループ全体を囲む一つのボーダー。"Remove"
            ボタンはこの行の子の一つではなく行自身のアクションであるため、
            ラベルの外側にとどめる——内側に置けば、Remove を押すことが
            フィールドへのフォーカスも兼ねてしまう。
          */}
          {visibleFields.length === 0 ? null : (
            <Card>
              {visibleFields.map((field) => (
                <Row
                  key={fieldKey(field)}
                  label={field.keyword}
                  warning={
                    [
                      field.dangerous === true ? t("host.dangerousField", { keyword: field.keyword }) : "",
                      field.duplicate === true ? t("host.duplicateKeyword") : "",
                    ]
                      .filter((part) => part !== "")
                      .join(" ") || undefined
                  }
                  action={
                    <Button
                      className="px-2 py-1 text-xs"
                      onClick={() =>
                        setRemoved(removed.includes(field.line)
                          ? removed.filter((line) => line !== field.line)
                          : [...removed, field.line])
                      }
                    >
                      {removed.includes(field.line) ? t("host.keep") : t("host.remove")}
                    </Button>
                  }
                >
                  <input
                    id={`field-${fieldKey(field)}`}
                    value={draftFor(field)}
                    disabled={!field.editable || removed.includes(field.line)}
                    onChange={(event) => setDrafts({ ...drafts, [fieldKey(field)]: event.target.value })}
                    className={control}
                  />
                </Row>
              ))}
            </Card>
          )}

          {tab === "Advanced" ? (
            <div className="flex flex-col gap-2 rounded border border-line p-3">
              <label htmlFor="new-directive" className="text-xs text-ink-muted">{t("host.newDirective")}</label>
              <input
                id="new-directive"
                value={newKeyword}
                onChange={(event) => setNewKeyword(event.target.value)}
                className={control}
              />
              <label htmlFor="new-value" className="text-xs text-ink-muted">{t("host.newValue")}</label>
              <input
                id="new-value"
                value={newValue}
                onChange={(event) => setNewValue(event.target.value)}
                className={control}
              />
              <button type="button" onClick={addDirective} className={`self-start ${secondaryAction}`}>
                {t("host.addDirective")}
              </button>
              {additions.length === 0 ? null : (
                <ul className="text-xs text-ink-muted">
                  {additions.map((addition, index) => (
                    <li key={`${addition.keyword ?? ""}-${index}`}>
                      {`${addition.keyword ?? ""} ${formatValues(addition.values ?? [])}`}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : null}

          <button type="button" onClick={submitFieldEdits} className={`self-start ${primaryAction}`}>
            {t("host.saveChanges")}
          </button>
        </div>
      ) : null}

      {tab === "Raw" ? (
        <div className="flex flex-col gap-2">
          <label htmlFor="block-raw" className="text-xs text-ink-muted">
            {t("host.blockText")}
          </label>
          <textarea
            id="block-raw"
            value={blockRaw}
            onChange={(event) => setBlockRaw(event.target.value)}
            rows={16}
            spellCheck={false}
            className="rounded border border-control-line bg-canvas p-3 font-mono text-xs"
          />
          <button type="button" onClick={() => onBlockRaw(blockRaw)} className={`self-start ${primaryAction}`}>
            {t("host.saveBlock")}
          </button>
        </div>
      ) : null}

      {tab === "Effective" ? (
        <div className="flex flex-col gap-2">
          <p role="status" className="text-xs text-notice-ink">
            {t("host.effectiveNote")}
          </p>
          <button
            type="button"
            onClick={() => setTab("Diagnostics")}
            className="self-start rounded border border-control-line px-2 py-1 text-xs"
          >
            {t("host.openDiagnostics")}
          </button>
          <ul className="flex flex-col gap-1">
            {detail.effective.entries.map((entry, index) => (
              <li key={`${entry.keyword}-${index}`} className="text-xs text-ink-muted">
                {`${entry.keyword} ${entry.values.join(" ")} — ${entry.source.path ?? entry.source.absolute ?? ""}:${entry.source.line ?? 0}`}
              </li>
            ))}
          </ul>
          <NoticeList notices={detail.effective.notices ?? []} />
        </div>
      ) : null}

      {tab === "Diagnostics" ? (
        // パターンで一致するブロックは宛先を名指さないため、発信・evaluate・
        // Terminal を開く対象が何もない。ConnectionsPage はそうしたものを
        // ここへ決してルーティングしないが、すべての検査を指定するのは alias で
        // あるため、空の alias はどこからもパネルへ届いてはならない。
        identityAlias === "" ? (
          <p className="text-sm text-ink-muted">
            {t("host.noDestination")}
          </p>
        ) : (
          <div className="flex flex-col gap-4">
            <DiagnosticsPanel api={integrations} host={identityAlias} />
            {/*
              保存されたパスワードはディレクティブではなく検査の側にある。
              設定の一部ではないからであり、この機能は
              ssh_config のバイトを一切書き込まない。
            */}
            <PasswordPanel api={integrations} alias={identityAlias} />
          </div>
        )
      ) : null}

      {/*
        ここにあるものはすべて接続の一つのプロパティであり、
        以前はキャプションとコントロールを交互に並べた単一の列として、
        グルーピングなしにレイアウトされていた——次のコントロールのキャプションが
        前のものへのヒントのように読めてしまう壁だった。各プロパティは
        今や自分自身の隙間を持つ自分自身の行である。

        残っているものはファイルへ書き込まれる。グループはディレクトリである
        ため、それを変えることはブロックの移動であり、comment は`Host`の
        上の行であり、名前変更は`Host`行そのものである。colour、tags、
        favourite flag、display order は metadata.json にのみ存在する
        ため、インスペクターへ移った——それこそがそのペインの存在理由である。
      */}
      {/*
        自分自身のボーダーは持たない。内側のカードが既に一つ描いており、
        ボーダーのある箱がボーダーのある箱を抱えると、一つしかないのに
        二つのグループのように見えてしまう。
      */}
      <section className="flex flex-col gap-3">
        <h3 className={sectionHeading}>{t("host.organisation")}</h3>

        {/*
          グループと alias はそれぞれ一行であるため行にする。comment は
          そうではない。三行の散文であり、その高さの箱の横に
          キャプションを置くと、その下の隙間のキャプションのように読めてしまう。
        */}
        <Card>
          <Row
            label={t("host.primaryGroup")}
            hint={`${t("host.groupIsADirectory")} ${t("host.groupNoneMeans")}`}
            action={
              <Button
                // 無効化するのは、選んだ先がすでに接続のいる場所である
                // ときだけである。以前は"None"も無効化されており、接続を
                // グループから外に戻す方法がマウスでもキーボードでも
                // まったくなかった。
                disabled={moveTo === (detail.form.entry.group ?? "")}
                onClick={() => onMoveToGroup(moveTo)}
              >
                {t("host.moveToGroup")}
              </Button>
            }
          >
            <select
              id="host-group"
              value={moveTo}
              onChange={(event) => setMoveTo(event.target.value)}
              className={narrowControl}
            >
              <option value="">{t("host.groupNone")}</option>
              {groups.map((group) => (
                <option key={group.name} value={group.name}>{group.name}</option>
              ))}
            </select>
          </Row>
          <Row
            label={t("host.renameAlias")}
            action={<Button onClick={() => onRename(renameTo)}>{t("host.rename")}</Button>}
          >
            <input
              id="host-rename"
              value={renameTo}
              onChange={(event) => setRenameTo(event.target.value)}
              className={control}
            />
          </Row>
        </Card>

        <div className="flex flex-col gap-2">
          <label htmlFor="host-comment" className={fieldLabel}>{t("host.comment")}</label>
          <textarea
            id="host-comment"
            value={comment}
            onChange={(event) => setComment(event.target.value)}
            rows={3}
            className={control}
          />
          <p className={hintText}>
            {detail.form.comment === "" && (detail.metadata.note ?? "") !== ""
              ? t("host.commentFromNote")
              : t("host.commentNote")}
          </p>
          <Button className="self-start" onClick={() => onComment(comment)}>
            {t("host.saveComment")}
          </Button>
        </div>

      </section>

      <SavePreviewPanel
        preview={preview}
        conflict={problem?.conflict ?? null}
        problem={problem}
      />
    </section>
  );
}
