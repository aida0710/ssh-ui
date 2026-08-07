import { useCallback, useEffect, useState } from "react";
import { RevealDialog } from "./RevealDialog";
import { CopyButton } from "../ui/CopyButton";
import { useTranslate, type Translate } from "../i18n/context";
import {
  CheckboxField,
  control,
  hintText,
  primaryAction,
  secondaryAction,
  sectionCard,
  sectionHeading,
  tableHeadCell,
  tableHeadRow,
} from "../ui/form";
import { Card, Row } from "../ui/surface";
import type { MessageKey } from "../i18n/messages";
import { integrationsApi, type Credential, type IntegrationsApi } from "../api/integrations";
import {
  keysApi,
  type KeyCertificate,
  type KeyInventoryResponse,
  type KeyItem,
  type KeysApi,
  type KeyVariant,
  type RelocateKeyResponse,
  type TrashListResponse,
} from "./api";

// groups は宣言済みのグループ名で、シェルが overview から渡す。
// Keys 画面はそれらを推測しない: ディレクトリがグループなのは
// ~/.ssh/config の行がそう言っているからで、その行を読むのは設定エンジンだけだ。
//
// secrets は vault であり、最初の面にメソッドを数個足したものではなく
// 第二の面である: 鍵とは何かはこのパッケージに属し、パスフレーズが
// どこにあるかは vault に属する。これはサーバーが鍵サービスと
// シークレットサービスの間で保つのと同じ分離だ。
type KeysScreenProps = { api?: KeysApi; groups?: string[]; secrets?: IntegrationsApi };

type ScreenState = "loading" | "ready" | "error";

// storedFor は、この鍵が既に指しているパスフレーズ(あれば)だ。vault は
// 名前とその使い道には答えるが値には決して答えないので、これが画面に
// 分かる唯一のことだ——そしてフィールドを空欄のままにしてよいと言うには十分だ。
function storedFor(phrases: Credential[], item: KeyItem): Credential | undefined {
  return phrases.find((credential) => credential.uses.includes(item.relativePath));
}

// certificateLines は OpenSSH の証明書を、使えるかどうかを決める
// 観点で記述する: 誰を名指すか、誰のためのものか、期限が切れているか
// どうかだ。「certificate」とだけ言う期限切れの証明書は動作するものと
// 見分けがつかない。これが design §6.3 がそれらを分類する理由のすべてだ。
function certificateLines(
  certificate: KeyCertificate,
  now: number,
  t: Translate,
): { text: string; expired: boolean }[] {
  const lines: { text: string; expired: boolean }[] = [];
  if (certificate.keyId !== "") lines.push({ text: t("keys.certKeyId", { keyId: certificate.keyId }), expired: false });
  if (certificate.principals.length > 0) {
    lines.push({ text: t("keys.certFor", { principals: certificate.principals.join(", ") }), expired: false });
  } else {
    // principal のない証明書は、その CA を信頼するホスト上の全ユーザーに
    // 対して有効だ。これはフィールドの欠落ではなく、その及ぶ範囲についての事実だ。
    lines.push({ text: t("keys.certAnyPrincipal"), expired: false });
  }
  if (certificate.neverExpires) {
    lines.push({ text: t("keys.certNeverExpires"), expired: false });
  } else {
    const expiry = new Date(certificate.validBefore * 1000);
    const expired = certificate.validBefore * 1000 <= now;
    const when = `${expiry.toISOString().slice(0, 16).replace("T", " ")}Z`;
    lines.push({ text: expired ? t("keys.certExpired", { when }) : t("keys.certValidUntil", { when }), expired });
  }
  if (certificate.signedKeyType !== "") {
    lines.push({
      text: t("keys.certSigns", {
        keyType: certificate.signedKeyType,
        fingerprint: certificate.signedKeyFingerprint,
      }).trim(),
      expired: false,
    });
  }
  return lines;
}

// 行のアクションはルールのないテーブルの中のただのボタンだったので、
// テキストとして連なり、コントロールではなく文章として読めてしまっていた。
// ボーダーとこれらのクラスが、鍵同士を隔てるものだ。
const rowAction = "rounded border border-control-line px-2 py-1 text-xs hover:bg-select-fill disabled:text-ink-faint";
const rowDanger = "rounded border border-control-line px-2 py-1 text-xs text-danger hover:bg-select-fill";

const noteLabels: Record<string, MessageKey> = {
  fingerprint_unavailable: "keys.noteFingerprintUnavailable",
  symbolic_link: "keys.noteSymbolicLink",
  empty_file: "keys.noteEmptyFile",
  not_regular_file: "keys.noteNotRegularFile",
  comment_not_preserved: "keys.noteCommentNotPreserved",
  keychain_entry_stale: "keys.noteKeychainEntryStale",
};

// ブロッカーは安定したコード、':'、それが指す詳細から成る。コードが
// 文を決め、詳細がそれを埋める。サーバーが後で追加する理由も、
// 捨てられることなく、それが指すパスをそのまま表示する。
const blockerLabels: Record<string, MessageKey> = {
  key_destination_occupied: "keys.blockerTargetOccupied",
  key_reference_unresolved: "keys.blockerUnresolved",
  key_reference_outside_workspace: "keys.blockerReferenceExternal",
  key_group_not_declared: "keys.blockerGroupNotDeclared",
  key_destination_is_config: "keys.blockerDestinationIsConfig",
  key_in_state_directory: "keys.blockerStateDirectory",
};

function describeBlocker(blocker: string, t: Translate): string {
  const separator = blocker.indexOf(":");
  const code = separator < 0 ? blocker : blocker.slice(0, separator);
  const detail = separator < 0 ? blocker : blocker.slice(separator + 1);
  return t(blockerLabels[code] ?? "keys.blockerOther", { detail });
}

// renameable は、ユーザーが伝えていないことを決めずに、このアプリケーションが
// ファイルをリネームできるかどうかを報告する。
//
// 秘密鍵は自分の公開鍵と証明書を道連れにするので、常にリネーム
// 可能だ。公開鍵や証明書がリネーム可能なのは、インベントリ内の
// どの秘密鍵もそれに属していない場合のみだ: ペアの片方だけをリネームすると、
// OpenSSH がいまだに名前で対応付けている 2 つのファイルを、読み手が
// 対応付けられなくなるので、サーバーはそれを拒否し、ボタンも提供されない。
function renameable(item: KeyItem, items: KeyItem[]): boolean {
  if (item.kind === "private_key") return true;
  if (item.kind !== "public_key" && item.kind !== "certificate") return false;
  const fingerprint =
    item.kind === "certificate" && item.certificate !== undefined
      ? item.certificate.signedKeyFingerprint
      : item.fingerprint;
  if (fingerprint === "") return true;
  return !items.some((candidate) => candidate.kind === "private_key" && candidate.fingerprint === fingerprint);
}

// groupOfKeyPath は、鍵が置かれている場所からそのグループを読み取り、
// サーバーの規則を映す: keys/<group>/<file> であり、それ以外はグループに属さない。
export function groupOfKeyPath(relativePath: string): string {
  const segments = relativePath.split("/");
  if (segments.length < 3 || segments[0] !== "keys") return "";
  return segments.slice(1, -1).join("/");
}

// relocateStem は、ユーザーが置き換えるよう求められている名前の部分だ。
// サーバーの規則を映しているので、フィールドはサーバーが拒否するであろう
// 名前ではなく、実際に relocation が変える名前から始まる。
function relocateStem(item: KeyItem): string {
  const base = item.relativePath.split("/").pop() ?? item.relativePath;
  if (item.kind === "private_key") return base;
  for (const suffix of ["-cert.pub", ".pub"]) {
    if (base.endsWith(suffix) && base.length > suffix.length) return base.slice(0, -suffix.length);
  }
  return base;
}

// agentHolds は、エージェントが現在この鍵を保持しているかどうかを、
// フィンガープリントで照合して報告する。エージェントの identity とインベントリ
// 項目に共通するのはそれだけだ——エージェントはファイルパスを何も知らない。
function agentHolds(inventory: KeyInventoryResponse, item: KeyItem): boolean {
  if (!inventory.agentAvailable || item.fingerprint === "") return false;
  return inventory.agentIdentities.some((identity) => identity.fingerprint === item.fingerprint);
}

export function KeysScreen({ api = keysApi, groups = [], secrets = integrationsApi }: KeysScreenProps) {
  const t = useTranslate();
  const [state, setState] = useState<ScreenState>("loading");
  const [inventory, setInventory] = useState<KeyInventoryResponse | null>(null);
  const [trash, setTrash] = useState<TrashListResponse | null>(null);
  const [variants, setVariants] = useState<KeyVariant[]>([]);
  const [algorithm, setAlgorithm] = useState("ed25519");
  const [fileName, setFileName] = useState("");
  const [comment, setComment] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [unencrypted, setUnencrypted] = useState(false);
  const [terminalCommand, setTerminalCommand] = useState<string[] | null>(null);
  const [revealing, setRevealing] = useState<KeyItem | null>(null);
  const [changingPassphrase, setChangingPassphrase] = useState<KeyItem | null>(null);
  const [currentPassphrase, setCurrentPassphrase] = useState("");
  const [newPassphrase, setNewPassphrase] = useState("");
  const [removePassphrase, setRemovePassphrase] = useState(false);
  const [registering, setRegistering] = useState<KeyItem | null>(null);
  const [phrases, setPhrases] = useState<Credential[]>([]);
  const [chosenPhrase, setChosenPhrase] = useState("");
  const [agentPassphrase, setAgentPassphrase] = useState("");
  const [agentLifetime, setAgentLifetime] = useState(0);
  const [storeInKeychain, setStoreInKeychain] = useState(false);
  const [publicKeyView, setPublicKeyView] = useState<{ relativePath: string; text: string } | null>(null);
  const [relocating, setRelocating] = useState<KeyItem | null>(null);
  const [newName, setNewName] = useState("");
  const [newGroup, setNewGroup] = useState("");
  const [relocated, setRelocated] = useState<RelocateKeyResponse | null>(null);
  const [createGroup, setCreateGroup] = useState("");
  const [pendingPurge, setPendingPurge] = useState("");
  const [pendingTrash, setPendingTrash] = useState<KeyItem | null>(null);
  const [failure, setFailure] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [nextInventory, nextTrash, nextAlgorithms] = await Promise.all([
        api.inventory(),
        api.listTrash(),
        api.algorithms(),
      ]);
      setInventory(nextInventory);
      setTrash(nextTrash);
      setVariants(nextAlgorithms.variants);
      setState("ready");
    } catch {
      setState("error");
    }
  }, [api]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const selected = variants.find((variant) => variant.algorithm === algorithm);
  const inProcess = selected === undefined || selected.inProcess;
  // 描画時に読み取るので、この画面が開いている間に期限が切れた証明書は、
  // 次に何かがそれを更新した時点で「有効」と説明されなくなる。
  const now = Date.now();

  async function submitGeneration() {
    setFailure("");
    setTerminalCommand(null);
    try {
      if (selected !== undefined && !selected.inProcess) {
        const response = await api.hardwareCommand({ algorithm, fileName, group: createGroup, comment });
        setTerminalCommand(response.command);
        return;
      }
      await api.generate({
        algorithm,
        bits: selected?.bits ?? 0,
        fileName,
        group: createGroup,
        comment,
        passphrase,
        unencrypted,
      });
      setPassphrase("");
      setFileName("");
      await refresh();
    } catch {
      setPassphrase("");
      setFailure(t("keys.createFailed"));
    }
  }

  function closePassphraseForm() {
    setCurrentPassphrase("");
    setNewPassphrase("");
    setRemovePassphrase(false);
    setChangingPassphrase(null);
  }

  // パスフレーズは 1 回の送信の間だけコンポーネント状態にとどまり、
  // 成功時にも失敗時にもクリアされる。他のどこにも保存されることはない。
  async function submitPassphrase(item: KeyItem) {
    setFailure("");
    try {
      await api.changePassphrase(item.id, {
        currentPassphrase,
        newPassphrase: removePassphrase ? "" : newPassphrase,
        unencrypted: removePassphrase,
      });
      closePassphraseForm();
      await refresh();
    } catch {
      setCurrentPassphrase("");
      setNewPassphrase("");
      setFailure(t("keys.passphraseFailed"));
    }
  }

  // エージェントに鍵を返すよう頼む。何も破棄されないので確認は不要だ:
  // 最悪の結果はもう一度パスフレーズを求められることだけだ。応答は
  // その後エージェントが保持しているものを伝え、画面はそれを再読み込みする。
  async function removeFromAgent(keyId: string) {
    try {
      await api.deregisterFromAgent(keyId);
      await refresh();
    } catch {
      setFailure(t("keys.agentRemoveFailed"));
    }
  }

  function closeAgentForm() {
    setAgentPassphrase("");
    setAgentLifetime(0);
    setStoreInKeychain(false);
    setChosenPhrase("");
    setPhrases([]);
    setRegistering(null);
  }

  // 名前はフォームが開いたときに読み込まれ、それより前ではない。起動時には
  // 何も尋ねられず、一度も鍵を登録しない画面は vault に一切触れない。
  // 閉じた vault は何も答えず、それはエラーではなくピッカーなしとして
  // 表示される: このフォームは vault がなくても動作するし、以前からそうだった。
  async function loadPhrases() {
    try {
      const listed = await secrets.credentials();
      setPhrases(listed.credentials.filter((credential) => credential.kind === "key_passphrase"));
    } catch {
      setPhrases([]);
    }
  }

  async function assignPhrase(item: KeyItem) {
    try {
      await secrets.assignCredential("key_passphrase", item.relativePath, chosenPhrase);
      await loadPhrases();
    } catch {
      setFailure(t("keys.assignPassphraseFailed"));
    }
  }

  // 登録操作は、パスフレーズ変更フォームとまったく同じ長さだけパスフレーズを
  // 保持する: 1 回の送信の間だけで、成功時にも失敗時にもクリアされる。
  // 応答はわざと捨てる——リフレッシュがインベントリを再読み込みするので、
  // その後画面が示すのは、エージェントが報告する保持内容であって、
  // このリクエストが主張した内容ではない。
  async function submitRegistration(item: KeyItem) {
    setFailure("");
    try {
      await api.registerWithAgent(item.id, {
        passphrase: agentPassphrase,
        lifetimeSeconds: agentLifetime,
        storeInKeychain,
      });
      closeAgentForm();
      await refresh();
    } catch {
      setAgentPassphrase("");
      setFailure(t("keys.agentFailed"));
    }
  }

  // 公開鍵は秘密ではないので、これは確認も監査記録もない普通の
  // 読み取りだ。コピーされる前に表示されるのは、この画面の他のすべての
  // 値と同じ理由による: クリップボードに載るのは、ユーザーが
  // 見ているものであるべきだ。
  async function showPublicKey(item: KeyItem) {
    setFailure("");
    try {
      const response = await api.publicKey(item.id);
      setPublicKeyView({ relativePath: response.relativePath, text: response.publicKey.trimEnd() });
    } catch {
      setPublicKeyView(null);
      setFailure(t("keys.publicKeyFailed"));
    }
  }

  function closeRelocateForm() {
    setNewName("");
    setNewGroup("");
    setRelocating(null);
  }

  // ブロックされた relocation は、報告して忘れるべき失敗ではない:
  // サーバーは何も書き込まず理由を伝えたので、その理由は画面に残り、
  // フォームはユーザーが入力した内容を残したまま開いたままになる。
  async function submitRelocation(item: KeyItem) {
    setFailure("");
    setRelocated(null);
    try {
      const currentGroup = groupOfKeyPath(item.relativePath);
      const response = await api.relocate(item.id, {
        ...(newName === relocateStem(item) ? {} : { newName }),
        ...(newGroup === currentGroup ? {} : { group: newGroup }),
      });
      setRelocated(response);
      if (response.blockers.length > 0) return;
      closeRelocateForm();
      await refresh();
    } catch {
      setFailure(t("keys.relocateFailed"));
    }
  }

  async function moveToTrash(keyId: string) {
    setFailure("");
    try {
      await api.trash(keyId);
      setPendingTrash(null);
      await refresh();
    } catch {
      setFailure(t("keys.trashFailed"));
    }
  }

  // 鍵はフィンガープリントグループ全体——秘密鍵とその隣の公開鍵——ごと
  // ごみ箱に送られ、それを名指すすべての IdentityFile は
  // 何も指さないまま取り残される。行は既にそれがどのホストかを示していたのに、
  // ボタンは一度もそれに触れず、1 回の押下で全体が実行された。
  function trashGroup(item: KeyItem): KeyItem[] {
    const fingerprint = item.fingerprint;
    if (fingerprint === "") return [item];
    return inventory === null
      ? [item]
      : inventory.items.filter((candidate) => candidate.fingerprint === fingerprint);
  }

  async function restore(entryId: string) {
    setFailure("");
    try {
      const response = await api.restore(entryId);
      if (response.blockers.length > 0) {
        setFailure(t("keys.restoreRefused", { blockers: response.blockers.join(", ") }));
        return;
      }
      await refresh();
    } catch {
      setFailure(t("keys.restoreFailed"));
    }
  }

  async function purge(entryId: string) {
    setFailure("");
    try {
      await api.purge(entryId);
      setPendingPurge("");
      await refresh();
    } catch {
      setFailure(t("keys.purgeFailed"));
    }
  }

  if (state === "loading") {
    return <p aria-live="polite">{t("keys.reading")}</p>;
  }
  if (state === "error" || inventory === null || trash === null) {
    return <p role="alert">{t("keys.unreadable")}</p>;
  }

  return (
    <section aria-labelledby="keys-heading" className="flex flex-col gap-8">
      <h2 id="keys-heading" className="text-lg font-medium">
        {t("keys.heading")}
      </h2>
      {failure !== "" && (
        <p role="alert" className="rounded-md border border-control-line p-3 text-sm text-danger">
          {failure}
        </p>
      )}

      <div className="overflow-x-auto">
      <table className="w-full min-w-[56rem] text-left text-sm">
        <caption className="sr-only">{t("keys.tableCaption")}</caption>
        <thead>
          <tr className={tableHeadRow}>
            <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colFile")}</th>
            <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colKind")}</th>
            <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colAlgorithm")}</th>
            <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colFingerprint")}</th>
            <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colPermissions")}</th>
            <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colUsedBy")}</th>
            <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colActions")}</th>
          </tr>
        </thead>
        <tbody>
          {inventory.items.map((item) => (
            <tr key={item.id} className="border-b border-line align-top">
              <td className="py-2 pr-3 font-mono text-xs">{item.relativePath}</td>
              <td className="py-2 pr-3">
                {item.kind}
                {item.certificate === undefined ? null : (
                  <ul className="text-xs text-ink-muted">
                    {certificateLines(item.certificate, now, t).map((line) => (
                      <li key={line.text} className={line.expired ? "text-danger" : undefined}>
                        {line.text}
                      </li>
                    ))}
                  </ul>
                )}
              </td>
              <td className="py-2 pr-3">{item.bits > 0 ? `${item.algorithm} · ${item.bits}` : item.algorithm}</td>
              <td className="py-2 pr-3 font-mono text-xs break-all">
                {item.fingerprint !== "" ? item.fingerprint : null}
                {item.notes.map((note) => (
                  <span key={note} className="ml-2 text-notice-ink">
                    {note in noteLabels ? t(noteLabels[note]!) : note}
                  </span>
                ))}
              </td>
              <td className="py-2 pr-3">
                {item.permission}
                {item.permissionRisk && <span className="ml-2 text-notice-ink">{t("keys.permissionRisk")}</span>}
              </td>
              <td className="py-2 pr-3">
                {item.references.map((reference) => reference.hostPatterns.join(" ")).join(", ")}
              </td>
              <td className="py-2">
                <div className="flex flex-wrap gap-1">
                {(item.kind === "public_key" || item.kind === "certificate") && (
                  <button type="button" className={rowAction} onClick={() => void showPublicKey(item)}>
                    {t("keys.showPublicKey")}
                  </button>
                )}
                {item.kind === "private_key" && (
                  <>
                    <button type="button" className={rowAction} onClick={() => setRevealing(item)}>
                      {t("keys.showPrivateKey")}
                    </button>
                    <button
                      type="button"
                      className={rowAction}
                      onClick={() => {
                        closePassphraseForm();
                        closeAgentForm();
                        setChangingPassphrase(item);
                      }}
                    >
                      {t("keys.changePassphrase")}
                    </button>
                    <button
                      type="button"
                      className={rowAction}
                      disabled={!inventory.agentAvailable}
                      onClick={() => {
                        closePassphraseForm();
                        closeAgentForm();
                        setRegistering(item);
                        if (item.encrypted) void loadPhrases();
                      }}
                    >
                      {t("keys.addToAgent")}
                    </button>
                    {agentHolds(inventory, item) && (
                      <button
                        type="button"
                        className={rowAction}
                        onClick={() => {
                          closePassphraseForm();
                          closeAgentForm();
                          void removeFromAgent(item.id);
                        }}
                      >
                        {t("keys.removeFromAgent")}
                      </button>
                    )}
                    <button
                      type="button"
                      className={rowAction}
                      onClick={() => {
                        closePassphraseForm();
                        closeAgentForm();
                        setPendingTrash(item);
                      }}
                    >
                      {t("keys.moveToTrash")}
                    </button>
                  </>
                )}
                {renameable(item, inventory.items) && (
                  <button
                    type="button"
                    className={rowAction}
                    onClick={() => {
                      closePassphraseForm();
                      closeAgentForm();
                      setRelocated(null);
                      setNewName(relocateStem(item));
                      setNewGroup(groupOfKeyPath(item.relativePath));
                      setRelocating(item);
                    }}
                  >
                    {t("keys.relocate")}
                  </button>
                )}
                </div>
              </td>
            </tr>
          ))}
          {inventory.items.length === 0 && (
            <tr>
              <td colSpan={7} className="py-3 text-sm text-ink-muted">
                {t("keys.inventoryEmpty")}
              </td>
            </tr>
          )}
        </tbody>
      </table>
      </div>

      {pendingTrash !== null && (
        <section aria-labelledby="trash-confirm-heading" className={sectionCard}>
          <h3 id="trash-confirm-heading" className={sectionHeading}>
            {t("keys.trashConfirmHeading", { path: pendingTrash.relativePath })}
          </h3>
          {/*
            公開鍵が秘密鍵の隣から消えても驚かないよう、どのファイルが
            消えるかを示す。両者は 1 つの鍵だからこそ一緒に移動する。
          */}
          <p className="text-sm text-ink">{t("keys.trashExplain")}</p>
          <ul className="flex flex-col gap-0.5 font-mono text-xs text-ink-muted">
            {trashGroup(pendingTrash).map((member) => (
              <li key={member.id}>{member.relativePath}</li>
            ))}
          </ul>
          {/*
            行は既にこの鍵を名指すホストを列挙していた。ここでそれを言うのは、
            決定と次回接続時の驚きとの違いだ:
            存在しないファイルを指す IdentityFile は、
            ssh が報告した上でそのまま続行してしまうものだ。
          */}
          {pendingTrash.references.length === 0 ? (
            <p className={hintText}>{t("keys.trashNoReferences")}</p>
          ) : (
            <>
              <p className="text-sm text-notice-ink">
                {t("keys.trashReferences", { count: pendingTrash.references.length })}
              </p>
              <ul className="flex flex-col gap-0.5 font-mono text-xs text-notice-ink">
                {pendingTrash.references.map((reference, index) => (
                  <li key={`${reference.configPath}-${reference.line}-${index}`}>
                    {`${reference.hostPatterns.join(" ")} — ${reference.configPath}:${reference.line}`}
                  </li>
                ))}
              </ul>
            </>
          )}
          <p className={hintText}>{t("keys.trashIsRecoverable")}</p>
          <div className="flex flex-wrap gap-2">
            <button type="button" className={rowDanger} onClick={() => void moveToTrash(pendingTrash.id)}>
              {t("keys.trashConfirm")}
            </button>
            <button type="button" className={secondaryAction} onClick={() => setPendingTrash(null)}>
              {t("keys.trashCancel")}
            </button>
          </div>
        </section>
      )}

      {publicKeyView !== null && (
        <section aria-labelledby="public-key-heading" className={sectionCard}>
          <h3 id="public-key-heading" className={sectionHeading}>
            {t("keys.publicKeyHeading", { path: publicKeyView.relativePath })}
          </h3>
          <pre aria-label={t("keys.publicKeyLabel")} className="overflow-x-auto rounded-md bg-canvas p-4 text-xs">
            {publicKeyView.text}
          </pre>
          <div className="flex gap-2">
            <CopyButton value={publicKeyView.text} label="copy.publicKey" />
            <button type="button" className={secondaryAction} onClick={() => setPublicKeyView(null)}>
              {t("keys.close")}
            </button>
          </div>
        </section>
      )}

      {/*
        スキャナが解釈を拒んだファイルは、以前は単にテーブルから欠落していただけで、
        それは不完全なインベントリを完全なものに見せていた。
        design §6.3 は ~/.ssh 配下のすべてを分類する。これらはそれが
        分類できなかった項目であり、そう言うことが「ここには何もない」と
        「ここには読めなかった何かがある」の違いになる。
      */}
      {inventory.unreadable.length > 0 && (
        <section aria-labelledby="unreadable-heading" className="flex flex-col gap-2">
          <h3 id="unreadable-heading" className="text-sm font-medium text-notice-ink">
            {t("keys.unreadableHeading")}
          </h3>
          <p className="text-sm text-ink-muted">{t("keys.unreadableNote")}</p>
          <ul className="text-sm text-ink-muted">
            {inventory.unreadable.map((file) => (
              <li key={file.relativePath}>{t("keys.unreadableEntry", { path: file.relativePath, reason: file.reason })}</li>
            ))}
          </ul>
        </section>
      )}

      {inventory.unresolvedReferences.length > 0 && (
        <section aria-labelledby="unresolved-heading" className="flex flex-col gap-2">
          <h3 id="unresolved-heading" className="text-sm font-medium text-notice-ink">
            {t("keys.unresolvedHeading")}
          </h3>
          <ul className="text-sm text-ink-muted">
            {inventory.unresolvedReferences.map((reference) => (
              <li key={`${reference.configPath}:${reference.line}:${reference.value}`}>
                {t("keys.referenceWithReason", {
                  directive: reference.directive,
                  value: reference.value,
                  path: reference.configPath,
                  line: reference.line,
                  reason: reference.reason,
                })}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section aria-labelledby="agent-heading" className="flex flex-col gap-2">
        <h3 id="agent-heading" className={sectionHeading}>
          {t("keys.agentHeading")}
        </h3>
        {inventory.agentAvailable ? (
          inventory.agentIdentities.length === 0 ? (
            <p className="text-sm text-ink-muted">{t("keys.agentEmpty")}</p>
          ) : (
            <table className="w-full min-w-[32rem] text-left text-sm">
              <caption className="sr-only">{t("keys.agentIdentitiesCaption")}</caption>
              <thead>
                <tr className={tableHeadRow}>
                  <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colAlgorithm")}</th>
                  <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colFingerprint")}</th>
                  <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colComment")}</th>
                </tr>
              </thead>
              <tbody>
                {inventory.agentIdentities.map((identity) => (
                  <tr key={identity.fingerprint} className="border-b border-line">
                    <td className="py-2 pr-3">
                      {identity.bits > 0 ? `${identity.algorithm} · ${identity.bits}` : identity.algorithm}
                    </td>
                    <td className="py-2 pr-3 font-mono text-xs break-all">{identity.fingerprint}</td>
                    <td className="py-2">{identity.comment}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        ) : (
          // ssh-add は SSH_AUTH_SOCK が指すものと話す。「エージェントが動いていない」
          // と言うのは推測になる: このプロセスに単にソケットが渡されて
          // いないだけかもしれない。メッセージは何が足りないかを言い、理由は言わない。
          <p className="text-sm text-notice-ink">
            {t("keys.agentUnavailable")}
          </p>
        )}
        {inventory.agentDelegations.length > 0 && (
          <>
            <p className="text-sm text-ink-muted">
              {t("keys.agentDelegationsNote")}
            </p>
            <ul className="text-sm text-ink-muted">
              {inventory.agentDelegations.map((reference) => (
                <li key={`${reference.configPath}:${reference.line}`}>
                  {t("keys.reference", {
                    directive: reference.directive,
                    value: reference.value,
                    path: reference.configPath,
                    line: reference.line,
                  })}
                  {reference.hostPatterns.length > 0 ? ` (${reference.hostPatterns.join(" ")})` : ""}
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      {registering !== null && (
        <form
          aria-labelledby="agent-register-heading"
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            void submitRegistration(registering);
          }}
        >
          <h3 id="agent-register-heading" className={sectionHeading}>
            {t("keys.registerHeading", { path: registering.relativePath })}
          </h3>
          <p className="text-sm text-ink-muted">{t("keys.registerNote")}</p>
          <Card>
            {registering.encrypted && (
              // 「Passphrase」ではなく「Key passphrase」: 下にある生成フォームには
              // それ自身のフィールドがあり、同じ名前の 2 つのコントロールでは
              // ユーザーが見分けられない。
              <Row
                label={t("keys.keyPassphrase")}
                {...(storedFor(phrases, registering) === undefined ? {} : { hint: t("keys.typedWins") })}
              >
                <input
                  className={control}
                  type="password"
                  value={agentPassphrase}
                  onChange={(event) => setAgentPassphrase(event.target.value)}
                />
              </Row>
            )}
            <Row label={t("keys.lifetime")}>
              <select
                className={control}
                value={String(agentLifetime)}
                onChange={(event) => setAgentLifetime(Number(event.target.value))}
              >
                <option value="0">{t("keys.lifetimeForever")}</option>
                <option value="3600">{t("keys.lifetimeHour")}</option>
                <option value="14400">{t("keys.lifetimeFourHours")}</option>
                <option value="43200">{t("keys.lifetimeTwelveHours")}</option>
              </select>
            </Row>
          </Card>
          {/*
            保存されたパスフレーズは、鍵の追加を 2 アクションではなく 1 アクションに
            変える。ここに現れるのは鍵のパスフレーズだけだ: このピッカーで
            アカウントパスワードを提供すれば、リモートホストのログイン資格情報を
            ローカルの鍵に渡すことになる。だからこそ vault は 2 つの名前空間を分けている。
          */}
          {registering.encrypted && storedFor(phrases, registering) !== undefined && (
            <p className={hintText}>
              {t("keys.usesStoredPassphrase", { name: storedFor(phrases, registering)!.name })}
            </p>
          )}
          {registering.encrypted && phrases.length > 0 && (
            <div className="flex flex-wrap items-end gap-3">
              <Row label={t("keys.useStoredPassphrase")}>
                <select
                  className={control}
                  value={chosenPhrase}
                  onChange={(event) => setChosenPhrase(event.target.value)}
                >
                  <option value="">{t("keys.choosePassphraseName")}</option>
                  {phrases.map((credential) => (
                    <option key={credential.name} value={credential.name}>
                      {credential.name}
                    </option>
                  ))}
                </select>
              </Row>
              <button
                type="button"
                className={secondaryAction}
                disabled={chosenPhrase === ""}
                onClick={() => void assignPhrase(registering)}
              >
                {t("keys.useThisPassphrase")}
              </button>
            </div>
          )}
          <CheckboxField
            label={t("keys.storeInKeychain")}
            checked={storeInKeychain}
            onChange={setStoreInKeychain}
          />
          <div className="flex gap-2">
            <button type="submit" className={primaryAction}>
              {t("keys.registerSubmit")}
            </button>
            <button type="button" className={secondaryAction} onClick={closeAgentForm}>
              {t("keys.cancel")}
            </button>
          </div>
        </form>
      )}

      {relocating !== null && (
        <form
          aria-labelledby="relocate-heading"
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            void submitRelocation(relocating);
          }}
        >
          <h3 id="relocate-heading" className={sectionHeading}>
            {t("keys.relocateHeading", { path: relocating.relativePath })}
          </h3>
          <p className="text-sm text-ink-muted">{t("keys.relocateNote")}</p>
          <Card>
            <Row label={t("keys.relocateNewName")}>
              <input className={control} value={newName} onChange={(event) => setNewName(event.target.value)} />
            </Row>
            <Row label={t("keys.relocateGroup")}>
              <select className={control} value={newGroup} onChange={(event) => setNewGroup(event.target.value)}>
                <option value="">{t("keys.groupNone")}</option>
                {groups.map((group) => (
                  <option key={group} value={group}>
                    {group}
                  </option>
                ))}
              </select>
            </Row>
          </Card>
          <div className="flex gap-2">
            <button type="submit" className={primaryAction}>
              {t("keys.relocateSubmit")}
            </button>
            <button type="button" className={secondaryAction} onClick={closeRelocateForm}>
              {t("keys.cancel")}
            </button>
          </div>
        </form>
      )}

      {/*
        リネームが何をしたか、あるいは何がそれを止めたか。どちらも同じ種類の事実の
        リストだ: どのファイルが移動したか、どの設定行が書き換えられたか、そして
        このアプリケーションが意図的に触れなかったものは何か。「完了」とだけ言う
        リネームは、ユーザー自身では確認できない部分を隠してしまう。
      */}
      {relocated !== null && (
        <section
          aria-labelledby="relocate-result-heading"
          className="flex flex-col gap-2 text-sm"
        >
          <h3 id="relocate-result-heading" className={sectionHeading}>
            {relocated.blockers.length > 0
              ? t("keys.relocateRefused")
              : t("keys.relocateDone", { path: relocated.relativePath })}
          </h3>
          {relocated.blockers.length > 0 && (
            <ul role="alert" className="text-notice-ink">
              {relocated.blockers.map((blocker) => (
                <li key={blocker}>{describeBlocker(blocker, t)}</li>
              ))}
            </ul>
          )}
          {relocated.files.length > 0 && (
            <>
              <h4 className="text-xs uppercase tracking-wide text-ink-muted">{t("keys.relocateMoved")}</h4>
              <ul className="font-mono text-xs text-ink-muted">
                {relocated.files.map((file) => (
                  <li key={file.from}>{t("keys.relocateFilePair", { from: file.from, to: file.to })}</li>
                ))}
              </ul>
            </>
          )}
          {relocated.references.length > 0 && (
            <>
              <h4 className="text-xs uppercase tracking-wide text-ink-muted">{t("keys.relocateRewritten")}</h4>
              <ul className="text-xs text-ink-muted">
                {relocated.references.map((reference) => (
                  <li key={`${reference.configPath}:${reference.line}:${reference.from}`}>
                    {t("keys.relocateReference", {
                      directive: reference.directive,
                      from: reference.from,
                      to: reference.to,
                      path: reference.configPath,
                      line: reference.line,
                    })}
                  </li>
                ))}
              </ul>
            </>
          )}
          {relocated.skipped.length > 0 && (
            <p className="text-ink-muted">{t("keys.relocateSkipped", { paths: relocated.skipped.join(", ") })}</p>
          )}
          {relocated.notes.map((note) => (
            <p key={note} className="text-notice-ink">
              {note in noteLabels ? t(noteLabels[note]!) : note}
            </p>
          ))}
          <div>
            <button type="button" className={secondaryAction} onClick={() => setRelocated(null)}>
              {t("keys.close")}
            </button>
          </div>
        </section>
      )}

      {revealing !== null && (
        <RevealDialog
          keyId={revealing.id}
          relativePath={revealing.relativePath}
          api={api}
          onClose={() => setRevealing(null)}
        />
      )}

      {changingPassphrase !== null && (
        <form
          aria-labelledby="passphrase-heading"
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            void submitPassphrase(changingPassphrase);
          }}
        >
          <h3 id="passphrase-heading" className={sectionHeading}>
            {t("keys.passphraseHeading", { path: changingPassphrase.relativePath })}
          </h3>
          <p className="text-sm text-ink-muted">{t("keys.passphraseNote")}</p>
          <Card>
            <Row label={t("keys.currentPassphrase")}>
              <input
                className={control}
                type="password"
                value={currentPassphrase}
                onChange={(event) => setCurrentPassphrase(event.target.value)}
              />
            </Row>
            <Row label={t("keys.newPassphrase")}>
              <input
                className={control}
                type="password"
                value={newPassphrase}
                onChange={(event) => setNewPassphrase(event.target.value)}
                disabled={removePassphrase}
              />
            </Row>
          </Card>
          <CheckboxField
            label={t("keys.removePassphrase")}
            checked={removePassphrase}
            onChange={(checked) => {
              setRemovePassphrase(checked);
              setNewPassphrase("");
            }}
          />
          <div className="flex gap-2">
            <button type="submit" className={primaryAction}>
              {t("keys.savePassphrase")}
            </button>
            <button type="button" className={secondaryAction} onClick={closePassphraseForm}>
              {t("keys.cancel")}
            </button>
          </div>
        </form>
      )}

      <form
        aria-labelledby="create-key-heading"
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          void submitGeneration();
        }}
      >
        <h3 id="create-key-heading" className={sectionHeading}>
          {t("keys.createHeading")}
        </h3>
        <Card>
          <Row label={t("keys.algorithm")}>
            <select className={control} value={algorithm} onChange={(event) => setAlgorithm(event.target.value)}>
              {variants.map((variant) => (
                <option key={`${variant.algorithm}-${variant.bits}`} value={variant.algorithm}>
                  {variant.label}
                </option>
              ))}
            </select>
          </Row>
          <Row label={t("keys.createGroup")}>
            <select className={control} value={createGroup} onChange={(event) => setCreateGroup(event.target.value)}>
              <option value="">{t("keys.groupNone")}</option>
              {groups.map((group) => (
                <option key={group} value={group}>
                  {group}
                </option>
              ))}
            </select>
          </Row>
          <Row label={t("keys.fileName")}>
            <input className={control} value={fileName} onChange={(event) => setFileName(event.target.value)} />
          </Row>
          <Row label={t("keys.comment")}>
            <input className={control} value={comment} onChange={(event) => setComment(event.target.value)} />
          </Row>
          {inProcess && (
            <Row label={t("keys.passphrase")}>
              <input
                className={control}
                type="password"
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
                disabled={unencrypted}
              />
            </Row>
          )}
        </Card>
        {inProcess && (
          <CheckboxField
            label={t("keys.createUnencrypted")}
            checked={unencrypted}
            onChange={(checked) => {
              setUnencrypted(checked);
              setPassphrase("");
            }}
          />
        )}
        <button type="submit" className={`self-start ${primaryAction}`}>
          {inProcess ? t("keys.createSubmit") : t("keys.showTerminalCommand")}
        </button>
      </form>

      {terminalCommand !== null && (
        <div>
          <p className="text-sm text-ink-muted">
            {t("keys.hardwareNote")}
          </p>
          <pre aria-label={t("copy.terminalCommand")} className="overflow-x-auto rounded-md bg-canvas p-4 text-xs">
            {terminalCommand.join(" ")}
          </pre>
          <div className="mt-2">
            <CopyButton value={terminalCommand.join(" ")} label="copy.terminalCommand" />
          </div>
        </div>
      )}

      <div className="flex flex-col gap-2">
        <h3 className={sectionHeading}>{t("keys.trashHeading")}</h3>
        <p className="text-sm text-ink-muted">{t("keys.trashNote")}</p>
        <div className="overflow-x-auto">
        <table className="w-full min-w-[40rem] text-left text-sm">
          <caption className="sr-only">{t("keys.trashCaption")}</caption>
          <thead>
            <tr className={tableHeadRow}>
              <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colFiles")}</th>
              <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colAge")}</th>
              <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colStatus")}</th>
              <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colActions")}</th>
            </tr>
          </thead>
          <tbody>
            {trash.entries.map((entry) => (
              <tr key={entry.id} className="border-b border-line align-top">
                <td className="py-2 pr-3 font-mono text-xs">
                  {entry.files.map((file) => file.originalRelativePath).join(", ")}
                </td>
                <td className="py-2 pr-3">
                  {entry.stale
                    ? t("keys.ageStale", { days: entry.ageDays, retention: trash.retentionDays })
                    : t("keys.age", { days: entry.ageDays })}
                </td>
                <td className="py-2 pr-3">{entry.restorable ? t("keys.restorable") : entry.blockers.join(", ")}</td>
                <td className="py-2">
                  <div className="flex flex-wrap items-center gap-1">
                  <button type="button" className={rowAction} onClick={() => void restore(entry.id)}>
                    {t("keys.restore")}
                  </button>
                  {pendingPurge === entry.id ? (
                    <>
                      <span>{t("keys.purgeWarning")}</span>
                      <button type="button" className={rowDanger} onClick={() => void purge(entry.id)}>
                        {t("keys.confirmPurge")}
                      </button>
                      <button type="button" className={rowAction} onClick={() => setPendingPurge("")}>
                        {t("keys.cancel")}
                      </button>
                    </>
                  ) : (
                    <button type="button" className={rowDanger} onClick={() => setPendingPurge(entry.id)}>
                      {t("keys.purge")}
                    </button>
                  )}
                  </div>
                </td>
              </tr>
            ))}
            {trash.entries.length === 0 && (
              <tr>
                <td colSpan={4} className="py-3 text-sm text-ink-muted">
                  {t("keys.trashEmpty")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        </div>
      </div>
    </section>
  );
}
