// このアプリケーションが翻訳されている 2 つの言語。英語が
// フォールバックなのは、カタログがその言語で書かれているからで、
// 未知のブラウザ言語はキーではなく完全な文へと縮退する。
export const locales = ["en", "ja"] as const;
export type Locale = (typeof locales)[number];

export const defaultLocale: Locale = "en";

// storageKey は、このアプリケーションが永続的なブラウザストレージに
// 書き込む唯一のものだ。導出ではなく名前を付けているのは、end-to-end
// スイートがこのキーだけを許可し、他は何であれ失敗させられる
// ようにするためだ——検証は許可リストであり、カウントでは好みとトークンを区別できない。
export const storageKey = "sshc.language";

export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && (locales as readonly string[]).includes(value);
}

// detectLocale は保存された選択を読み、次にブラウザの申告を読み、
// 最後に英語へフォールバックする。
//
// ストレージへのアクセスを包んでいるのは、拒否するよう設定されたブラウザが
// 読み取り時に例外を投げるためだ。言語設定は、シェル全体を失敗させてまで
export function detectLocale(): Locale {
  try {
    const stored = window.localStorage.getItem(storageKey);
    if (isLocale(stored)) return stored;
  } catch {
    // 守る価値はない。使えない場合は、ブラウザ自身の言語がそのまま適用される。
  }
  // "ja-JP" と "ja" はどちらも日本語を意味する。文字列全体ではなく
  // サブタグを照合することで、地域変種すべてが機能し続ける。
  for (const candidate of navigator.languages ?? [navigator.language]) {
    const subtag = candidate.split("-")[0];
    if (isLocale(subtag)) return subtag;
  }
  return defaultLocale;
}

export function rememberLocale(locale: Locale): void {
  try {
    window.localStorage.setItem(storageKey, locale);
  } catch {
    // その選択はこのタブには引き続き適用されるが、タブを超えては残らない。
  }
}
