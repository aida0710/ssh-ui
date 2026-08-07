import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { messages, type MessageKey } from "./messages";
import { defaultLocale, detectLocale, rememberLocale, type Locale } from "./locale";

// メッセージに埋め込む値。数値も受け付けるのは、件数は
// 1 個の値として読め、呼び出し側全員に文字列化を強いるのは雑音だからだ。
export type Values = Record<string, string | number>;

export type Translate = (key: MessageKey, values?: Values) => string;

type LanguageState = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: Translate;
};

const LanguageContext = createContext<LanguageState | null>(null);

// interpolate は {name} を渡された値で置き換える。
//
// 値のないプレースホルダは "undefined" に置き換えず、
// そのまま残す。波括弧が残っていれば引数の渡し忘れだと
// 一目で分かるが、文中の "undefined" は内容に見えてしまう。
function interpolate(template: string, values: Values | undefined): string {
  if (values === undefined) return template;
  return template.replace(/\{(\w+)\}/g, (whole, name: string) =>
    name in values ? String(values[name]) : whole,
  );
}

export function LanguageProvider({ children, initial }: { children: ReactNode; initial?: Locale }) {
  // detectLocale はマウント時に一度だけ実行する。後で読み直すのは
  // 切り替えと衝突する——日本語システムで英語を選ぶユーザーはそれを意図している。
  const [locale, setLocaleState] = useState<Locale>(() => initial ?? detectLocale());

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    rememberLocale(next);
  }, []);

  const value = useMemo<LanguageState>(() => {
    const catalogue = messages[locale];
    return {
      locale,
      setLocale,
      // 選択した言語にキーがなければ、キー名をそのまま表示せず
      // 英語にフォールバックする。TypeScript は既にそれを
      // 不可能にしている——日本語カタログは英語のものから型付け
      // されるからだ——ので、これは実行時に読み込まれる
      // カタログのみを対象とし、`keys.addToAgent` ではなく読める文へ縮退する。
      t: (key, values) => interpolate(catalogue[key] ?? messages[defaultLocale][key], values),
    };
  }, [locale, setLocale]);

  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
}

// プロバイダの外で描画されたパネルは、例外を投げるのではなく英語のまま表示され、
// コンポーネントテストがシェル全体を組み立てずに 1 枚のパネルを描画できるようにする。
// これは実際の危険でもある——プロバイダの外に配線されたパネルは
// 英語では正しく見えてしまい、他の誰にとってもずっと英語のままになる——ので、
// この不変条件はここで強制するのではなく表明するにとどめる。App がプロバイダを
// マウントすることは `App renders every panel inside the language provider` が
// 証明し、画面が実際に切り替わることは end-to-end の言語仕様が証明する。
const fallback: LanguageState = {
  locale: defaultLocale,
  setLocale: () => undefined,
  t: (key, values) => interpolate(messages[defaultLocale][key], values),
};

export function useLanguage(): LanguageState {
  return useContext(LanguageContext) ?? fallback;
}

export function useTranslate(): Translate {
  return useLanguage().t;
}
