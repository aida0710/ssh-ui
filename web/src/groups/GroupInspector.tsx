import type { GroupMetadata } from "../api/config";
import { CheckboxField, Field, control, fieldLabel, hintText } from "../ui/form";
import { Button, Card } from "../ui/surface";
import { useTranslate } from "../i18n/context";

// グループについての、metadata.json にのみ存在する三つのこと。
//
// 接続と同じ区分である。ファイルが記録するものはメインペインへ、
// このアプリケーションだけが知るものはここへ。グループの名前変更は
// ディレクトリを移動し Include 行を書き換えるが、colour を与えることはしない。
export function GroupInspector({
  group,
  members,
  onUpdate,
}: {
  group: GroupMetadata;
  // その接続。hiding をそもそも提示するかどうかを決める。
  members: string[];
  onUpdate: (patch: Partial<GroupMetadata>) => void;
}) {
  const t = useTranslate();
  const colour = group.colour === undefined || group.colour === "" ? "" : group.colour;

  return (
    <div className="flex flex-col gap-4">
      <h3 className={fieldLabel}>{t("inspector.appOnly")}</h3>

      <Card padded>
        <Field label={t("groups.colour")}>
          <input
            id={`group-colour-${group.name}`}
            type="color"
            // colour 入力欄には空の状態がないため、未設定の colour は
            // 中立の見本を示し、クリア操作はそれ自体独立した行為である。
            value={colour === "" ? "#8e8e93" /* palette-exempt: ネイティブコントロール自身の中立色 */ : colour}
            onChange={(event) => onUpdate({ colour: event.target.value })}
            className="h-8 w-14 rounded border border-control-line bg-control"
          />
        </Field>
        {colour === "" ? null : (
          <Button className="self-start" onClick={() => onUpdate({ colour: "" })}>
            {t("groups.clearColour", { name: group.name })}
          </Button>
        )}

        <Field label={t("groups.displayOrder")}>
          <input
            id={`group-order-${group.name}`}
            type="number"
            value={String(group.order ?? 0)}
            onChange={(event) => onUpdate({ order: Number(event.target.value) || 0 })}
            className={control}
          />
        </Field>

        {/*
          hiding は他のグループを保持することが目的のグループのための
          ものである。自分自身の接続を持つグループではそれらも
          一緒に見えなくなってしまうため、黙って何もしないフラグを
          立てさせるのではなく、そこではコントロールを拒否する。
        */}
        <CheckboxField
          label={t("groups.hide", { name: group.name })}
          checked={group.hidden === true}
          disabled={members.length > 0}
          onChange={(checked) => onUpdate({ hidden: checked })}
        />
        {members.length === 0 ? null : <p className={hintText}>{t("groups.hideOnlyContainers")}</p>}
      </Card>
    </div>
  );
}
