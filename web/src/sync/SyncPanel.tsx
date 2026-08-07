import { useCallback, useEffect, useState } from "react";
import { failureCode } from "../api/client";
import {
  integrationsApi,
  type IntegrationsApi,
  type PullResponse,
  type SyncDirection,
  type SyncStatus,
} from "../api/integrations";
import { useTranslate } from "../i18n/context";
import type { MessageKey } from "../i18n/messages";
import {
  Field,
  control,
  hintText,
  primaryAction,
  secondaryAction,
  sectionHeading,
} from "../ui/form";
import { Card, Notice, Row } from "../ui/surface";

type SyncPanelProps = { api?: IntegrationsApi };

// この画面が出会いうる拒否に、名前を付けたもの。サーバーがわざわざ
// 区別したコードは、ユーザーが対処できるコードであり、「それはできなかった」
// では見当違いの場所を探させてしまう: 打ち間違えたマスターパスワードは
// バケットの問題ではなく、パスを含むエンドポイントは資格情報の問題ではない。
const refusals: Record<string, MessageKey> = {
  wrong_master_password: "sync.wrongMaster",
  bucket_refused: "sync.unreachable",
  sync_failed: "sync.unreachable",
  endpoint_must_have_no_path: "sync.endpointPath",
};

// リモートのスナップショット。
//
// この画面のすべては意図的な行為だ。pull はまずプレビューし、
// 2 回目の押下でのみ適用する。これはこのアプリケーションの他のあらゆる
// 書き込みが取る形と同じであり、衝突は解決されるのではなく表示される。
export function SyncPanel({ api = integrationsApi }: SyncPanelProps) {
  const t = useTranslate();
  const [status, setStatus] = useState<SyncStatus | null>(null);
  const [endpoint, setEndpoint] = useState("");
  const [bucket, setBucket] = useState("");
  const [path, setPath] = useState("");
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretAccessKey, setSecretAccessKey] = useState("");
  const [direction, setDirection] = useState<SyncDirection>("both");
  const [master, setMaster] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [preview, setPreview] = useState<PullResponse | null>(null);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    try {
      setStatus(await api.syncStatus());
    } catch {
      setError(t("sync.statusFailed"));
    }
  }, [api, t]);

  useEffect(() => {
    void reload();
  }, [reload]);

  // explain は、サーバーが名指した拒否をそのための文へと変える。
  // これにより、失敗の仕方が複数ある呼び出し側が、どれが起きたかを言える。
  async function run<T>(
    operation: () => Promise<T>,
    apply: (value: T) => void,
    failure: string,
    explain?: (code: string) => string,
  ) {
    setError("");
    setNotice("");
    setBusy(true);
    try {
      apply(await operation());
    } catch (caught) {
      const code = failureCode(caught);
      const named = refusals[code];
      setError(explain?.(code) || (named === undefined ? failure : t(named)));
    } finally {
      setBusy(false);
    }
  }

  if (status === null) {
    return <p role="status" className={hintText}>{t("sync.loading")}</p>;
  }

  // 閉じた vault はこのフォームを埋められず、push も pull もそれが
  // 保持する設定なしには実行できない。それでもフォームを見せれば
  // 「バケットが消えた」と読め、アクセスキーの再入力をユーザーに促してしまう。
  // それはまさに、保存することが防ぐはずだったことだ。
  if (status.locked) {
    return (
      <div className="flex flex-col gap-4">
        <h2 className="font-medium">{t("sync.heading")}</h2>
        {error === "" ? null : <Notice tone="danger">{error}</Notice>}
        <section className="flex flex-col gap-3">
          <h3 className={sectionHeading}>{t("sync.bucketHeading")}</h3>
          <p className="text-sm text-ink-muted">{t("sync.sealed")}</p>
          <Field label={t("secrets.master")}>
            <input
              type="password"
              value={master}
              onChange={(event) => setMaster(event.target.value)}
              className={control}
            />
          </Field>
          <button
            type="button"
            disabled={busy || master === ""}
            onClick={() =>
              void run(
                () => api.unlockVault(master),
                () => {
                  setMaster("");
                  void reload();
                },
                // 一度も vault を作ったことのないマシンは、マスターパスワードが
                // 間違っていたマシンではない。そう言ってしまえば、誰かに存在しない
                // パスワードを探し回らせてしまう。
                t("sync.unlockFailed"),
                (code) => (code === "vault_missing" ? t("sync.noVault") : ""),
              )
            }
            className={`self-start ${primaryAction}`}
          >
            {t("secrets.unlock")}
          </button>
        </section>
      </div>
    );
  }

  const conflicted = (preview?.conflicts ?? []).length > 0;

  return (
    <div className="flex flex-col gap-4">
      <h2 className="font-medium">{t("sync.heading")}</h2>
      {/*
        フォームの後ではなく前に伝える。~/.ssh の中身はすべて、秘密鍵を
        含めて移動する。バケットとそれらの間にあるのは
        パスフレーズだけだ。
      */}
      <p className={hintText}>{t("sync.warning")}</p>
      {error === "" ? null : <Notice tone="danger">{error}</Notice>}
      {notice === "" ? null : <p role="status" className="text-sm text-ink-muted">{notice}</p>}

      <section className="flex flex-col gap-3">
        <h3 className={sectionHeading}>{t("sync.bucketHeading")}</h3>
        {status.configured ? (
          <p className="font-mono text-xs text-ink-muted">
            {[status.endpoint, status.bucket, status.path].filter((part) => part !== "" && part !== undefined).join("/")}
          </p>
        ) : (
          <p className="text-sm text-ink-muted">{t("sync.notConfigured")}</p>
        )}
        {/*
          積み重なったフィールドの 2 列グリッドではなく、行を持つ 1 枚のカードだ。
          ここのヒントは完全な文であり、コントロールの脇に置けば
          半分の列に押し込まれてしまうが、行の下ならその幅がある。
        */}
        <Card>
          <Row label={t("sync.endpoint")} hint={t("sync.endpointHint")}>
            <input
              value={endpoint}
              onChange={(event) => setEndpoint(event.target.value)}
              placeholder="https://<account>.r2.cloudflarestorage.com"
              className={control}
            />
          </Row>
          <Row label={t("sync.bucket")}>
            <input value={bucket} onChange={(event) => setBucket(event.target.value)} className={control} />
          </Row>
          {/*
            空欄はバケットのルートを意味し、これがよくある場合だ: バケットは
            通常このアプリケーション用に既に名前が付けられており、その中で
            名前を繰り返すフォルダは何もない階層をもう 1 つ重ねるだけだ。
          */}
          <Row label={t("sync.path")} hint={t("sync.pathHint")}>
            <input value={path} onChange={(event) => setPath(event.target.value)} className={control} />
          </Row>
          <Row label={t("sync.accessKeyId")}>
            <input
              value={accessKeyId}
              onChange={(event) => setAccessKeyId(event.target.value)}
              className={control}
            />
          </Row>
          {/*
            資格情報はマスターパスワードで封印され、vault の中ではなくその隣に
            保管される。vault は持ち運ばれるが、バケットへの鍵はそうであっては
            ならない。さもないと、1 つのスナップショットを入手した誰もが、
            以降のすべてを取得できてしまう。
          */}
          <Row label={t("sync.secretAccessKey")} hint={t("sync.credentialsNote")}>
            <input
              type="password"
              value={secretAccessKey}
              onChange={(event) => setSecretAccessKey(event.target.value)}
              className={control}
            />
          </Row>
          {/*
            このマシンがデータをどちらの向きに動かしてよいか。これは 2 つの
            書き込みを統べる: 送信に設定されたマシンは決して他のマシンのバイト列を
            適用されず、受信に設定されたマシンは決してバケットに書き込まない。
            プレビューはどちらにせよ使えるので、適用できないマシンでも
            自分がどれだけ遅れているかを知ることはできる。
          */}
          <Row label={t("sync.direction")} hint={t(`sync.direction.${direction}.hint`)}>
            <select
              value={direction}
              onChange={(event) => setDirection(event.target.value as SyncDirection)}
              className={control}
            >
              <option value="both">{t("sync.direction.both")}</option>
              <option value="push">{t("sync.direction.push")}</option>
              <option value="pull">{t("sync.direction.pull")}</option>
            </select>
          </Row>
        </Card>
        <button
          type="button"
          disabled={busy || endpoint === "" || bucket === "" || accessKeyId === "" || secretAccessKey === ""}
          onClick={() =>
            void run(
              () => api.configureSync({ endpoint, bucket, path, accessKeyId, secretAccessKey, direction }),
              (next) => {
                setStatus(next);
                setAccessKeyId("");
                setSecretAccessKey("");
              },
              t("sync.configureFailed"),
            )
          }
          className={`self-start ${primaryAction}`}
        >
          {t("sync.configure")}
        </button>
      </section>

      <section className="flex flex-col gap-3">
        <h3 className={sectionHeading}>{t("sync.snapshotHeading")}</h3>
        <p className={hintText}>
          {status.synced
            ? t("sync.lastSynced", { at: status.lastSyncedAt ?? "", count: status.fileCount ?? 0 })
            : t("sync.neverSynced")}
        </p>
        <Card>
          <Row label={t("sync.passphrase")} hint={t("sync.passphraseLost")}>
          <input
            type="password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
            className={control}
          />
          </Row>
        </Card>
        {status.direction === "both" ? null : (
          // 拒否はボタンが押されたときだけでなく、ボタンがある場所に
          // 述べられる: 隣に理由のない無効化されたコントロールは、設定ではなく
          // アプリケーションの不具合に見えてしまう。
          <p role="status" className="text-sm text-notice-ink">
            {t(`sync.direction.${status.direction}.active`)}
          </p>
        )}
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={busy || !status.configured || passphrase === "" || status.direction === "pull"}
            onClick={() =>
              void run(
                () => api.pushSnapshot(passphrase),
                (next) => {
                  setStatus(next);
                  setPreview(null);
                  setNotice(t("sync.pushed"));
                },
                t("sync.pushFailed"),
              )
            }
            className={primaryAction}
          >
            {t("sync.push")}
          </button>
          <button
            type="button"
            disabled={busy || !status.configured || passphrase === ""}
            onClick={() =>
              void run(
                () => api.pullSnapshot(passphrase, false),
                (next) => {
                  setPreview(next);
                  setNotice(
                    next.written.length + next.removed.length + next.conflicts.length === 0
                      ? t("sync.alreadyMatches")
                      : "",
                  );
                },
                t("sync.pullFailed"),
              )
            }
            className={secondaryAction}
          >
            {t("sync.preview")}
          </button>
        </div>
      </section>

      {preview === null ? null : (
        <section className="flex flex-col gap-3">
          <h3 className={sectionHeading}>{t("sync.previewHeading")}</h3>
          {conflicted ? (
            <>
              {/*
                両方が変更した 2 つのファイルに、正しいマージはない。どちらかを
                推測すれば、パーサーが守るために存在するバイト保存の約束を
                破ることになるので、これはどのファイルかを述べて止まる。
              */}
              <p className="text-sm text-notice-ink">{t("sync.conflictExplain")}</p>
              <ul className="flex flex-col gap-1 font-mono text-xs text-notice-ink">
                {preview.conflicts.map((conflict) => (
                  <li key={conflict.path}>{conflict.path}</li>
                ))}
              </ul>
            </>
          ) : null}
          {preview.written.length === 0 ? null : (
            <>
              <p className={hintText}>{t("sync.wouldWrite", { count: preview.written.length })}</p>
              <ul className="flex flex-col gap-1 font-mono text-xs text-ink-muted">
                {preview.written.map((path) => (
                  <li key={path}>{path}</li>
                ))}
              </ul>
            </>
          )}
          {preview.removed.length === 0 ? null : (
            <>
              <p className={hintText}>{t("sync.wouldRemove", { count: preview.removed.length })}</p>
              <ul className="flex flex-col gap-1 font-mono text-xs text-danger">
                {preview.removed.map((path) => (
                  <li key={path}>{path}</li>
                ))}
              </ul>
            </>
          )}
          <button
            type="button"
            disabled={
              busy ||
              conflicted ||
              status.direction === "push" ||
              preview.written.length + preview.removed.length === 0
            }
            onClick={() =>
              void run(
                () => api.pullSnapshot(passphrase, true),
                (next) => {
                  setPreview(next);
                  setNotice(t("sync.applied"));
                  void reload();
                },
                t("sync.applyFailed"),
              )
            }
            className={`self-start ${primaryAction}`}
          >
            {t("sync.apply")}
          </button>
        </section>
      )}
    </div>
  );
}
