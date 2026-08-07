import type { HostDetail, HostMetadata } from "../api/config";
import { CheckboxField, Field, control, fieldLabel, hintText } from "../ui/form";
import { Button, Card } from "../ui/surface";
import { useTranslate } from "../i18n/context";
import { NoticeList } from "./SavePreview";

// ペインに開く価値のある中身があるかどうか。
//
// トグルのアンバードットを駆動しているのはこれである。これがなければ、
// 既定で閉じているペインへ通知を移すことは、`duplicate_alias`を
// 持つ接続が持たないものとまったく同じに見えることを意味し、
// それではペインが改善ではなく後退になってしまう。
export function hostNeedsAttention(detail: HostDetail): boolean {
  return (detail.form.notices ?? []).length > 0 || (detail.effective.notices ?? []).length > 0;
}

// 値が継承されているのは、それを設定した行が別のファイルにあるときで
// ある。Effective タブは依然としてすべての値とその由来を列挙する。
// これは「これはどこから来たのか」という短い答えであり、ペインはその問いのためにある。
function inherited(detail: HostDetail) {
  const own = detail.form.entry.file.path ?? detail.form.entry.file.absolute;
  return detail.effective.entries.filter((entry) => (entry.source.path ?? entry.source.absolute) !== own);
}

export function HostInspector({
  detail,
  onMetadata,
}: {
  detail: HostDetail;
  onMetadata: (metadata: HostMetadata) => void;
}) {
  const t = useTranslate();
  const notices = [...(detail.form.notices ?? []), ...(detail.effective.notices ?? [])];
  const fromElsewhere = inherited(detail);

  return (
    <div className="flex flex-col gap-5">
      {/*
        カードにまとめてはいるが、その中では label-left/value-right では
        なく縦に積む。このペインは幅 17rem で、これらのキャプションは文である
        ——"Display order — lower sorts earlier; 0 leaves this host where
        the file puts it"をコントロールの横に置けば、コントロールは数文字幅しか
        残らない。Xcode のインスペクターも同じ理由で縦に積む。
      */}
      <section className="flex flex-col gap-3">
        <h3 className={fieldLabel}>{t("inspector.appOnly")}</h3>

        <Card padded>
        <CheckboxField
          label={t("host.favourite")}
          checked={detail.metadata.favourite === true}
          onChange={(checked) => onMetadata({ ...detail.metadata, favourite: checked })}
        />

        <div className="flex flex-col gap-2">
          <Field label={t("host.colour")}>
            <input
              type="color"
              // colour 入力欄には空の状態がないため、「colour がない」とは
              // メタデータ内に値が存在しないことであり、このコントロールはそれに
              // 対して中立の見本を示す。クリア操作は分離した明示的な行為で
              // ある。そうでなければ「colour がない」ことと「たまたまグレーで
              // ある colour」が区別できなくなる。
              value={
                detail.metadata.colour === undefined || detail.metadata.colour === ""
                  ? "#8e8e93" /* palette-exempt: ネイティブコントロール自身の中立色 */
                  : detail.metadata.colour
              }
              onChange={(event) => onMetadata({ ...detail.metadata, colour: event.target.value })}
              className="h-8 w-14 rounded border border-control-line bg-control"
            />
          </Field>
          {detail.metadata.colour === undefined || detail.metadata.colour === "" ? null : (
            <Button className="self-start" onClick={() => onMetadata({ ...detail.metadata, colour: "" })}>
              {t("host.clearColour")}
            </Button>
          )}
        </div>

        <Field label={t("host.tags")}>
          <input
            value={(detail.metadata.tags ?? []).join(", ")}
            onChange={(event) =>
              onMetadata({
                ...detail.metadata,
                tags: event.target.value
                  .split(",")
                  .map((tag) => tag.trim())
                  .filter((tag) => tag !== ""),
              })
            }
            className={control}
          />
        </Field>

        <Field label={t("host.displayOrder")}>
          <input
            type="number"
            value={String(detail.metadata.order ?? 0)}
            onChange={(event) => onMetadata({ ...detail.metadata, order: Number(event.target.value) || 0 })}
            className={control}
          />
        </Field>
        </Card>
      </section>

      <section className="flex flex-col gap-2">
        <h3 className={fieldLabel}>{t("inspector.notices")}</h3>
        {notices.length === 0 ? (
          <p className={hintText}>{t("inspector.noNotices")}</p>
        ) : (
          <NoticeList notices={notices} />
        )}
      </section>

      <section className="flex flex-col gap-2">
        <h3 className={fieldLabel}>{t("inspector.inherited")}</h3>
        {fromElsewhere.length === 0 ? (
          <p className={hintText}>{t("inspector.noInherited")}</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {fromElsewhere.map((entry, index) => (
              <li key={`${entry.keyword}-${index}`} className="text-xs text-ink-muted">
                {`${entry.keyword} ${entry.values.join(" ")} — ${
                  entry.source.path ?? entry.source.absolute ?? ""
                }:${entry.source.line ?? 0}`}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
