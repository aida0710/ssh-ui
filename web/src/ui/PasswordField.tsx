import { useState, type ReactNode } from "react";
import { useTranslate } from "../i18n/context";
import { Field, control } from "./form";

type PasswordFieldProps = {
  label: string;
  value: string;
  onChange: (value: string) => void;
  hint?: string;
  autoFocus?: boolean;
};

// 読み返せるパスワードフィールド。
//
// このアプリケーションが求めるすべてのパスワードは、打ち間違えたら
// ユーザーが復元できないものだ——マスターパスワードは特にそうだ——そして
// 中身を決して見せないフィールドは、誤字をどの文字が間違っていたかを
// 言わない拒否から後で知ることになるものにしてしまう。トグルは
// フィールドごとなので、1 つを開示しても隣のものは開示されない。
//
// ボタンは意図的に label の外に置く。label は自分のコントロールを
// 包んで両者を関連付け、その中の他のすべての語がそのコントロールの
// accessible name の一部になる: トグルをその中に置くと、フィールドは
// 自身を「Master password Show」と読み上げ、名前で探す何ものもそれを見つけられなかった。
export function PasswordField({ label, value, onChange, hint, autoFocus }: PasswordFieldProps): ReactNode {
  const t = useTranslate();
  const [shown, setShown] = useState(false);
  return (
    <div className="flex items-end gap-2">
      <div className="grow">
        <Field label={label} {...(hint === undefined ? {} : { hint })}>
          <input
            type={shown ? "text" : "password"}
            value={value}
            autoFocus={autoFocus ?? false}
            onChange={(event) => onChange(event.target.value)}
            className={control}
          />
        </Field>
      </div>
      {/*
        それが開示するフィールドにちなんで名付けているので、3 つある画面には
        3 つとも「Show」と呼ばれるのではなく、見分けられる 3 つのボタンがある。
      */}
      <button
        type="button"
        onClick={() => setShown(!shown)}
        aria-pressed={shown}
        aria-label={t(shown ? "password.hideNamed" : "password.showNamed", { label })}
        className="whitespace-nowrap rounded border border-control-line px-2 py-1.5 text-xs text-ink-muted hover:bg-select-fill"
      >
        {shown ? t("password.hide") : t("password.show")}
      </button>
    </div>
  );
}
