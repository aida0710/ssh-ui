import { useEffect, useState } from "react";
import { integrationsApi, type IntegrationsApi, type UpdateStatus } from "../api/integrations";
import { useTranslate } from "../i18n/context";

type UpdateBadgeProps = { api?: IntegrationsApi };

// バージョンと、より新しいものが公開されているかどうか。
//
// このチェックは、このアプリケーションが GitHub に対して行うリクエストだ
// ——自分自身以外に接続する唯一のホストだ——そしてページからではなく
// サーバーから行うので、ページの connect-src は 'self' のままになる。
// これはマウント時に実行され、それ以外では実行されない。
//
// ボタンではなくリンクを提供する。動いているバイナリをリリースの
// バイトで置き換える機能はかつてここにあったが、今はない: それを
// 守っていた署名はリリースワークフローが読める鍵を必要としたが、
// それはリポジトリを管理する者なら誰でも読める鍵であり、防御側と
// 攻撃側が同じ鍵を持っていたことになる。残っているのは有用な半分
// ——新しいバージョンがあると知ること——であり、決定は人に委ねられている。
export function UpdateBadge({ api = integrationsApi }: UpdateBadgeProps) {
  const t = useTranslate();
  const [status, setStatus] = useState<UpdateStatus | null>(null);

  useEffect(() => {
    let active = true;
    void api
      .updateStatus()
      .then((loaded) => {
        if (active) setStatus(loaded);
      })
      // ネットワークのないマシンでも、自分のバージョンは表示し続ける。ただし
      // より新しいものがあるかどうかは言えない。
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [api]);

  if (status === null) {
    return null;
  }
  return (
    <div className="border-t border-line px-2 py-2 text-xs text-ink-muted">
      <p>{t("update.version", { version: status.current })}</p>
      {!status.available || status.pageUrl === undefined ? null : (
        <p className="mt-1">
          <a
            href={status.pageUrl}
            target="_blank"
            rel="noreferrer noopener"
            className="text-ink underline underline-offset-2"
          >
            {t("update.available", { version: status.latest ?? "" })}
          </a>
        </p>
      )}
    </div>
  );
}
