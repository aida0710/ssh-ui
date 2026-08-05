// The message catalogue.
//
// `en` is the source of truth: its keys define MessageKey, and `ja` is typed as
// a complete record of them, so a translation that is missing or misspelled is
// a compile error rather than a key rendered on screen. Adding a message means
// adding it to both, which is the point.
//
// The English text is the wording that was already in the components, kept
// byte-for-byte. A translation is a translation; it is not an opportunity to
// quietly reword the original.
//
// {placeholders} are substituted by the provider. Japanese word order differs
// from English, so a message that would need concatenation in one language is
// written as one string with placeholders in both.
export const en = {
  "shell.title": "SSH UI",
  "shell.starting": "Starting secure local session…",
  "shell.active": "Local session active · {version}",
  "shell.bootstrapFailed":
    "Secure local session could not be started. Restart ssh-ui and use the newly opened tab.",
  "shell.primaryNavigation": "Primary",
  "shell.language": "Language",
  "shell.languageEnglish": "English",
  "shell.languageJapanese": "日本語",

  "section.connections": "Connections",
  "section.config": "Config",
  "section.groups": "Groups",
  "section.keys": "Keys",
  "section.knownHosts": "Known Hosts",
  "section.remoteKeys": "Remote Keys",
  "section.diagnostics": "Diagnostics",
  "section.history": "History",

  "copy.button": "Copy {label}",
  "copy.done": "Copied.",
  "copy.refused": "The browser refused to write to the clipboard.",
  "copy.command": "command",
  "copy.terminalCommand": "Terminal command",
  "copy.privateKey": "private key",
  "copy.publicKey": "public key",
  "copy.keyLine": "key line",
  "copy.remoteCommand": "remote command",

  "history.requestRejected": "The request was rejected ({code}).",
  "history.interrupted": "Interrupted transactions",
  "history.interruptedDetail": "{operation} started {startedAt}: {committed} of {total} files were written.",
  "history.complete": "Complete",
  "history.rollBack": "Roll back",
  "history.completed": "Completed changes",
  "history.empty": "No change has been made through this application yet.",
  "history.restorePath": "Restore {path}",
  "history.backupsKept":
    "Generation backups are kept in ~/.ssh/ssh-ui/backups and are never deleted automatically. A restore is itself a new transaction, so it can be undone the same way.",

  "notice.complex_external_rule": "A wildcard, negation, Match block or duplicate alias makes this value come from a rule this editor will not simplify. The source is shown instead.",
  "notice.duplicate_alias": "Another block declares the same alias. OpenSSH uses the first one it reads.",
  "notice.wildcard_shadow": "A catch-all block can override values for this host.",
  "notice.negated_pattern": "A negated pattern applies here.",
  "notice.unnamed_host_block": "This block has no concrete alias and can only be edited as raw text.",
  "notice.match_block": "A Match block was found. It is never evaluated here because Match exec can run a command.",
  "notice.dangerous_directive": "This directive can run a command. It is saved as written and never executed by this application.",
  "notice.unstructured_line": "This line has unbalanced quoting and is preserved exactly as written.",
  "notice.external_file": "This file is outside ~/.ssh. It is shown but never written.",
  "notice.orphan_metadata": "The host this note belonged to is gone. Re-associate it deliberately.",
  "notice.group_cycle": "This group's parents form a cycle, so it was skipped.",
  "notice.group_member_missing": "This group member has no host block in the configuration.",
  "notice.explained_values_only": "These values explain what this engine reads. Run ssh -G from the Diagnostics tab for the authoritative answer.",
  "notice.destination_not_included": "No Include reaches this file yet, so OpenSSH will not read the moved connection until you add one.",

  "preview.heading": "Save preview",
  "preview.newFile": " (new file)",
  "preview.tooLarge": "This file is too large for a line-by-line preview, so the whole file is shown as replaced.",
  "preview.syntaxError": "Syntax error in {path} at line {line}, column {column}. The edit is kept here and was not written.",
  "preview.theFile": "the file",
  "preview.graphError": "This change would break the Include graph. Nothing was written.",
  "preview.conflictError": "The file changed outside this application. Nothing was written.",
  "preview.rejected": "The request was rejected ({code}). Nothing was written.",
  "preview.changedOnDisk": "Changed on disk since you loaded it",
  "preview.pendingChange": "Your pending change",
  "preview.mergeByHand": "Reload the file to merge the two changes by hand. Nothing was written.",
  "preview.nothingYet": "Change a value to see exactly what would be written.",
  "preview.explainedFor": "Explained values for {alias}",
  "preview.unset": "unset",

  "reveal.heading": "Show private key: {path}",
  "reveal.warning":
    "The private key will be displayed in this page and can be copied by anyone who can read this window. This application cannot protect it from browser extensions or from clipboard history tools. Every reveal is recorded in history, without the key itself.",
  "reveal.show": "Show private key",
  "reveal.requesting": "Requesting a one-time confirmation…",
  "reveal.privateKeyLabel": "Private key",
  "reveal.failed": "The private key could not be shown. Close this dialog and confirm again.",
  "reveal.close": "Close",

  "orphan.heading": "Settings whose connection is gone",
  "orphan.explain":
    "These notes were written for a Host block that is no longer in your configuration. ssh-ui does not guess which connection inherited them.",
  "orphan.chooseTarget": "Choose the connection this note belongs to.",
  "orphan.occupied": "{alias} already has its own settings. Clear those first, or discard this note.",
  "orphan.entry": "{alias} in {path}",
  "orphan.noSettings": "no settings",
  "orphan.group": "group {group}",
  "orphan.tags": "tags {tags}",
  "orphan.favourite": "favourite",
  "orphan.note": "note “{note}”",
  "orphan.colour": "colour {colour}",
  "orphan.reassociateWith": "Re-associate {alias} with",
  "orphan.reassociatePlaceholder": "Re-associate with…",
  "orphan.reassociate": "Re-associate {alias}",
  "orphan.discard": "Discard {alias} settings",
} as const;

export type MessageKey = keyof typeof en;

export const ja: Record<MessageKey, string> = {
  "shell.title": "SSH UI",
  "shell.starting": "ローカルセッションを開始しています…",
  "shell.active": "ローカルセッション有効 · {version}",
  "shell.bootstrapFailed":
    "ローカルセッションを開始できませんでした。ssh-ui を再起動し、新しく開いたタブを使ってください。",
  "shell.primaryNavigation": "メインナビゲーション",
  "shell.language": "言語",
  "shell.languageEnglish": "English",
  "shell.languageJapanese": "日本語",

  "section.connections": "接続",
  "section.config": "設定ファイル",
  "section.groups": "グループ",
  "section.keys": "鍵",
  "section.knownHosts": "Known Hosts",
  "section.remoteKeys": "リモート公開鍵",
  "section.diagnostics": "診断",
  "section.history": "履歴",

  "copy.button": "{label}をコピー",
  "copy.done": "コピーしました。",
  "copy.refused": "ブラウザがクリップボードへの書き込みを拒否しました。",
  "copy.command": "コマンド",
  "copy.terminalCommand": "Terminal コマンド",
  "copy.privateKey": "秘密鍵",
  "copy.publicKey": "公開鍵",
  "copy.keyLine": "鍵の行",
  "copy.remoteCommand": "リモートコマンド",

  "history.requestRejected": "要求が拒否されました（{code}）。",
  "history.interrupted": "中断したトランザクション",
  "history.interruptedDetail": "{operation} 開始 {startedAt}: {total} 個のうち {committed} 個のファイルが書き込まれました。",
  "history.complete": "完了させる",
  "history.rollBack": "巻き戻す",
  "history.completed": "完了した変更",
  "history.empty": "このアプリケーションを通した変更はまだありません。",
  "history.restorePath": "{path} を復元",
  "history.backupsKept":
    "世代バックアップは ~/.ssh/ssh-ui/backups に保存され、自動では削除されません。復元自体も新しいトランザクションなので、同じ方法で取り消せます。",

  "notice.complex_external_rule": "ワイルドカード、否定、Match ブロック、alias の重複のいずれかにより、この値はこのエディタが単純化しない規則から来ています。代わりに出所を表示します。",
  "notice.duplicate_alias": "別のブロックが同じ alias を宣言しています。OpenSSH は最初に読んだものを使います。",
  "notice.wildcard_shadow": "catch-all ブロックがこのホストの値を上書きすることがあります。",
  "notice.negated_pattern": "否定パターンがここに適用されます。",
  "notice.unnamed_host_block": "このブロックには具体的な alias がなく、Raw テキストとしてのみ編集できます。",
  "notice.match_block": "Match ブロックが見つかりました。Match exec はコマンドを実行しうるため、ここでは評価しません。",
  "notice.dangerous_directive": "このディレクティブはコマンドを実行しうります。記述どおりに保存され、このアプリケーションが実行することはありません。",
  "notice.unstructured_line": "この行は引用符が対応しておらず、記述されたまま保持されます。",
  "notice.external_file": "このファイルは ~/.ssh の外にあります。表示のみで、書き込みは行いません。",
  "notice.orphan_metadata": "このメモが属していたホストがなくなりました。意識的に再関連付けしてください。",
  "notice.group_cycle": "このグループの親が循環しているため、スキップしました。",
  "notice.group_member_missing": "このグループのメンバーに対応する Host ブロックが設定にありません。",
  "notice.explained_values_only": "これらの値はこのエンジンが読んだ内容の説明です。権威ある答えは Diagnostics タブの ssh -G で確認してください。",
  "notice.destination_not_included": "このファイルへ届く Include がまだないため、移動した接続を OpenSSH は読みません。Include を追加してください。",

  "preview.heading": "保存プレビュー",
  "preview.newFile": "（新規ファイル）",
  "preview.tooLarge": "このファイルは行単位のプレビューには大きすぎるため、全体が置換として表示されます。",
  "preview.syntaxError": "{path} の {line} 行 {column} 列に構文エラーがあります。編集はここに保持され、書き込まれていません。",
  "preview.theFile": "対象ファイル",
  "preview.graphError": "この変更は Include グラフを壊します。何も書き込まれていません。",
  "preview.conflictError": "このファイルはアプリケーションの外で変更されました。何も書き込まれていません。",
  "preview.rejected": "要求が拒否されました（{code}）。何も書き込まれていません。",
  "preview.changedOnDisk": "読み込み後にディスク上で変更された内容",
  "preview.pendingChange": "保留中の変更",
  "preview.mergeByHand": "ファイルを読み込み直して 2 つの変更を手で統合してください。何も書き込まれていません。",
  "preview.nothingYet": "値を変更すると、何が書き込まれるかがここに表示されます。",
  "preview.explainedFor": "{alias} の説明された値",
  "preview.unset": "未設定",

  "reveal.heading": "秘密鍵を表示: {path}",
  "reveal.warning":
    "秘密鍵はこのページに表示され、このウィンドウを読める人なら誰でもコピーできます。ブラウザ拡張やクリップボード履歴ツールからは、このアプリケーションでは保護できません。表示した事実は履歴に記録されます（鍵そのものは記録しません）。",
  "reveal.show": "秘密鍵を表示",
  "reveal.requesting": "一度限りの確認を要求しています…",
  "reveal.privateKeyLabel": "秘密鍵",
  "reveal.failed": "秘密鍵を表示できませんでした。このダイアログを閉じて、もう一度確認してください。",
  "reveal.close": "閉じる",

  "orphan.heading": "接続がなくなった設定",
  "orphan.explain":
    "これらのメモは、設定にもう存在しない Host ブロックに対して書かれたものです。ssh-ui はどの接続が引き継いだかを推測しません。",
  "orphan.chooseTarget": "このメモが属する接続を選んでください。",
  "orphan.occupied": "{alias} には既に独自の設定があります。先にそちらを消すか、このメモを破棄してください。",
  "orphan.entry": "{path} の {alias}",
  "orphan.noSettings": "設定なし",
  "orphan.group": "グループ {group}",
  "orphan.tags": "タグ {tags}",
  "orphan.favourite": "お気に入り",
  "orphan.note": "メモ「{note}」",
  "orphan.colour": "色 {colour}",
  "orphan.reassociateWith": "{alias} の再関連付け先",
  "orphan.reassociatePlaceholder": "再関連付け先…",
  "orphan.reassociate": "{alias} を再関連付け",
  "orphan.discard": "{alias} の設定を破棄",
};

export const messages = { en, ja } satisfies Record<string, Record<MessageKey, string>>;
