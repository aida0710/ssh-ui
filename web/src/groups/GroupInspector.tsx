import type { GroupMetadata } from "../api/config";
import { CheckboxField, Field, control, fieldLabel, hintText } from "../ui/form";
import { Button } from "../ui/surface";
import { useTranslate } from "../i18n/context";

// The three things about a group that exist only in metadata.json.
//
// The same division as the connection's: what a file records goes in the main
// pane, what only this application knows goes here. Renaming a group moves
// directories and rewrites Include lines; giving it a colour does not.
export function GroupInspector({
  group,
  members,
  onUpdate,
}: {
  group: GroupMetadata;
  // Its connections, which decide whether hiding is offered at all.
  members: string[];
  onUpdate: (patch: Partial<GroupMetadata>) => void;
}) {
  const t = useTranslate();
  const colour = group.colour === undefined || group.colour === "" ? "" : group.colour;

  return (
    <div className="flex flex-col gap-4">
      <h3 className={fieldLabel}>{t("inspector.appOnly")}</h3>

      <div className="flex flex-col gap-3 rounded-xl border border-line bg-card p-3">
        <Field label={t("groups.colour")}>
          <input
            id={`group-colour-${group.name}`}
            type="color"
            // A colour input has no empty state, so an unset colour shows a
            // neutral swatch and clearing is its own act.
            value={colour === "" ? "#8e8e93" : colour}
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
          Hiding is for a group whose purpose is to hold other groups. One with
          connections of its own would take them out of view with it, so the
          control is refused there rather than left to set a flag that quietly
          does nothing.
        */}
        <CheckboxField
          label={t("groups.hide", { name: group.name })}
          checked={group.hidden === true}
          disabled={members.length > 0}
          onChange={(checked) => onUpdate({ hidden: checked })}
        />
        {members.length === 0 ? null : <p className={hintText}>{t("groups.hideOnlyContainers")}</p>}
      </div>
    </div>
  );
}
