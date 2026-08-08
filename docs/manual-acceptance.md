# 手動受け入れ試験

自動テストが決して行わない操作をここに集めます。設計 §10.5 のとおり、実リモート接続、実 `authorized_keys` 変更、実 Keychain、実 Terminal 起動は自動化しません。

実施前に必ず読むこと。

- 実施は使い捨ての `HOME` で行い、本番の `~/.ssh` では行いません。
  `work="$(mktemp -d)"; cp -R ~/.ssh "$work/.ssh"; HOME="$work" ./bin/sshc`
- 本番の `~/.ssh` を使う項目（Keychain と Terminal）は、事前に `~/.ssh` と `~/.ssh/sshc` を別ディレクトリへ退避してから行います。
- 各項目に日付、macOS と OpenSSH のバージョン、結果を記録します。

## M1. 実リモートホストへの接続テスト

1. 使い捨て `HOME` に、自分が管理する検証用ホストの `Host` ブロックを作る。
2. Diagnostics タブで「到達性」を実行し、`ProxyJump は使用していない` という注記が出ることを確認する。
3. 「認証テスト」を実行する。
4. 期待: 認証成功が報告され、stderr は 8 KiB 以内に切り詰められ、鍵本文もパスフレーズも表示されない。
5. 実行可能ディレクティブを持つ設定では、確認ダイアログに実際のコマンド文字列が表示され、確認するまで開始しないことを確認する。
6. Known Hosts パネルで「Scan」を実行し、候補が「unverified」と表示されること、別経路で得た fingerprint を入力するか明示的に承認するまで「Add to known_hosts」が押せないことを確認する。`ssh-keyscan` は実際に接続するため、この確認は自動テストに含めていません。

## M2. 実 `authorized_keys` への公開鍵登録

1. 検証用リモートホストに、削除してよい検証用ユーザーを用意する。
2. Remote Keys パネルで alias と公開鍵行を入力し、「Show what this would do」を押す。対象 alias、実効ユーザー、宛先、fingerprint、追記される 1 行、リモートで実行される固定スクリプトが表示されることを確認する。ここまでは自動 E2E でも確認しています。
3. 「Register the key」を実行し、リモートの `~/.ssh` が `0700`、`authorized_keys` が `0600` になっていることを `ls -l` で確認する。
4. 同じ鍵をもう一度登録し、`already_present` として重複行が増えないことを確認する。
5. POSIX shell を持たないリモート（例: 制限付きシェル）に対しては、手順の表示のみになることを確認する。この判定は実際に接続してみるまで分からないため、事前に警告する手段はありません。
6. 登録した行をリモートから削除して原状復帰する。

## M3. 実 macOS Keychain と ssh-agent

1. 本番の `~/.ssh` を退避したうえで実施する。
2. Keys 画面で鍵の行の「Add to agent」を押し、ライフタイムと「login Keychain に保存する」を選んで登録し、`ssh-add -l` に現れることを確認する。
3. 画面の ssh-agent 節が、`ssh-add -l` と同じ fingerprint を同じ数だけ表示していることを確認する。
4. `security find-generic-password -s "SSH: <path>"` で Keychain 項目が作られたことを確認する。
5. `ssh-add -d <path>` と Keychain 項目の削除で原状復帰する。
6. パスフレーズが `ps` の出力にも環境変数にも現れないことを、登録中に `ps -Eww -p $(pgrep ssh-add)` で確認する。

自動テストが到達できるのは、agent が無い状態の拒否だけです（`web/e2e/keys.spec.ts`）。実際に登録が成立することを示せるのはこの手動試験だけです。

## M4. 実 Terminal 起動

1. 接続画面で Terminal.app を選び、安全な alias の「接続」を実行して、Terminal.app が前面に来て `ssh -- <alias>` が実行されることを確認する。
2. iTerm2 を選んで同じ操作を行い、新しいiTerm2ウィンドウで接続が始まることを確認する。
3. `/Applications/kitty.app` をインストールした状態で kitty を選び、新しいkittyウィンドウで接続が始まることを確認する。
4. それぞれ保存済みパスワードを割り当てたホストでも試し、履歴とスクロールバックにパスワード、askpass URL、トークンが現れないことを確認する。
5. `sshc connect` を実行し、alias・User・HostNameの部分文字列で絞り込め、上下キーとEnterで現在のターミナルがSSHセッションへ切り替わることを確認する。
6. 安全でない alias（空白、引用符、先頭ハイフンを含むもの）では起動ボタンが無効で、コピー用コマンドと警告だけが表示されることを確認する。

## M5. 実 `~/.ssh` での読み取り専用リハーサル

1. 本番の `~/.ssh` をコピーした使い捨て `HOME` で起動する。
2. Connections、Config、Groups、Keys、Known Hosts、Remote Keys、Diagnostics、History の各画面を開くだけで、何も保存しない。
3. 終了後、`diff -r ~/.ssh "$work/.ssh"` が `sshc/` 配下以外で差分を出さないことを確認する。
4. 期待: 読み取りだけで既存ファイルが 1 バイトも変わらない。

## M6. 鍵の移動と実 macOS Keychain

自動テストは Keychain に触れられません。`ssh-add --apple-use-keychain` がこのリポジトリで唯一の Keychain 経路で、`security(1)` はどこでも使っていません。移動前に出す警告は文章であり、項目が実在するか、壊れるか、再登録で直るかは、この手順だけが証拠になります。

1. 使い捨て `HOME` で鍵を生成し、Keys 画面から `--apple-use-keychain` 付きで agent に登録する。
2. `security find-generic-password -s "SSH: <絶対パス>"` で項目が作られていることを確認する。
3. Keys 画面でその鍵の名前かグループを変更する。結果パネルに Keychain の警告が出ていることを確認する。
4. 再度 `security find-generic-password -s "SSH: <旧絶対パス>"` を実行し、項目が**古いパスのまま**であることを確認する。
5. `ssh -o IdentitiesOnly=yes -i <新パス> <host>` がパスフレーズを再度要求することを確認する。
6. Keys 画面から新しいパスで再登録し、`security find-generic-password -s "SSH: <新絶対パス>"` で新しい項目ができることを確認する。古い項目は手作業で削除する。
7. 期待: 移動そのものは成功し、Keychain の項目だけが古いパスに取り残される。アプリケーションはそれを警告するが、確認も修復もしない。

## 記録

未実施は空欄のままにせず「未実施」と書きます。空欄は「実施したが記録し忘れた」と区別がつきません。

| 日付 | 項目 | macOS | OpenSSH | 結果 | 備考 |
|---|---|---|---|---|---|
| — | M1 | — | — | 未実施 | 検証用リモートホストが必要 |
| — | M2 | — | — | 未実施 | 削除してよいリモートアカウントが必要 |
| — | M3 | — | — | 未実施 | 本番 `~/.ssh` の退避が必要 |
| — | M4 | — | — | 未実施 | 本番 `~/.ssh` の退避が必要 |
| — | M5 | — | — | 未実施 | 本番 `~/.ssh` のコピーが必要 |
| — | M6 | — | — | 未実施 | 実 Keychain と使い捨て `HOME` が必要 |
