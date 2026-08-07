import type { HostDetail, HostMetadata } from "../api/config";
import { CheckboxField, Field, control, fieldLabel, hintText } from "../ui/form";
import { Button, Card } from "../ui/surface";
import { useTranslate } from "../i18n/context";
import { NoticeList } from "./SavePreview";

// Whether the pane has something in it worth opening for.
//
// This is what the toggle's amber dot is driven by. Without it, moving the
// notices into a pane that is shut by default would mean a connection with
// `duplicate_alias` looked exactly like one without — which would make the
// pane a regression rather than an improvement.
export function hostNeedsAttention(detail: HostDetail): boolean {
  return (detail.form.notices ?? []).length > 0 || (detail.effective.notices ?? []).length > 0;
}

// A value is inherited when the line that set it is in another file. The
// Effective tab still lists every value and its source; this is the short
// answer to "where did this come from", which is the question the pane is for.
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
        Grouped in a card, but stacked inside it rather than label-left /
        value-right. This pane is 17rem wide and these captions are sentences —
        "Display order — lower sorts earlier; 0 leaves this host where the file
        puts it" beside a control would leave the control a few characters
        wide. Xcode's inspector stacks for the same reason.
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
              // A colour input has no empty state, so "no colour" is the absence
              // of the value in metadata and this control shows a neutral swatch
              // for it. Clearing is a separate, explicit act: otherwise "no
              // colour" is indistinguishable from "the colour that happens to
              // be grey".
              value={
                detail.metadata.colour === undefined || detail.metadata.colour === ""
                  ? "#8e8e93" /* palette-exempt: the native control's own neutral */
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
