# ssh-ui

`ssh-ui` は macOS 上で動く、OpenSSH クライアント管理 UI の基盤です。現在の foundation は、React UI を埋め込んだ単一の Go バイナリ、localhost セッション、CSRF 防御、厳格な Host/Origin 検査までを提供します。

## 前提環境と固定バージョン

- macOS arm64
- Go 1.26.5（`go.mod` の toolchain で固定）
- Node.js 22.19.0
- npm 11.7.0
- Echo v5.3.1、React 19.2.8、Vite 8.1.5、TypeScript 5.9.3、Tailwind CSS 4.3.3、Vitest 4.1.1

Echo v5 は、foundation の再現可能なビルドのため意図的に v5.3.1 へ固定しています。Go と npm の依存グラフは `go.sum` と `web/package-lock.json` で固定します。

## セットアップ

パッケージのインストールは環境を変更します。内容と対象を確認し、意識的に実行してください。このリポジトリ自身が自動でシステムパッケージをインストールすることはありません。

公式配布物で上記の Go、Node.js、npm を用意した後、frontend 依存をプロジェクト内へ復元する場合だけ次を実行します。

```sh
npm ci --prefix web
```

Go module は `make generate`、`make test`、`make build` の初回実行時に Go が module cache へ取得する場合があります。取得を許可する前に `go.mod` と `go.sum` を確認してください。

## 開発コマンド

```sh
make generate         # OpenAPI から Go/TypeScript 型を再生成
make verify-generated # 生成物が契約と一致することを確認
make test             # Go、race detector、Vitest、TypeScript を検証
make fuzz             # 全 fuzz target を既定 30 秒ずつ実行（FUZZTIME で変更）
make e2e              # バイナリをビルドし Playwright で主要フローを検証
make build            # UI を生成し bin/ssh-ui へ単一バイナリを作成
```

`./bin/ssh-ui` を起動すると、OS の既定ブラウザで一度限りの bootstrap fragment を持つ URL を開きます。Ctrl-C または SIGTERM で localhost サーバーを停止します。

## セキュリティ境界

- HTTP サーバーは IPv4 の `127.0.0.1` だけに bind します。LAN、Tailnet、コンテナ外部など、ネットワークへ公開して安全な設計ではありません。
- この foundation はまだ実際の `~/.ssh` を読みません。SSH config、鍵、Keychain、Terminal、リモートホストへアクセスする機能は含みません。
- bootstrap、session、CSRF の値をログへ出してはいけません。bootstrap は URL fragment に置き、ブラウザが直ちに履歴から除去します。
- 同一マシン上の悪意あるプロセス、侵害されたブラウザ、ブラウザ拡張から秘密を完全には保護できません。将来の秘密鍵 reveal/copy 機能でも、ブラウザ拡張やローカルのクリップボード監視・履歴ツールに対して秘密は脆弱です。
- UI は埋め込みファイルシステムからのみ配信し、URL を OS ファイルパスへ変換しません。存在しない API は SPA へフォールバックしません。

## SSH config エンジンの境界

- `~/.ssh/config` と `Include` 先を正本として読み書きします。無変更の parse/render は byte-for-byte で一致し、コメント、空行、引用、`key=value`、未知のディレクティブを保持します。
- 解釈できない行は `LineUnstructured` として原文のまま保持し、UI からは Raw 編集だけを許可します。推測による整形や削除は行いません。
- 書き込みは解決済みの `~/.ssh` 配下だけに限定します。`..`、シンボリックリンク、外部パスで書き込み範囲は広がりません。読み取りは `O_NOFOLLOW` を使います。
- `Include` が `~/.ssh` の外を指す場合は、グラフ表示と読み取りのみ許可します。
- `%h` など接続先が決まるまで確定しないトークンは展開せず、`include_unsupported_expansion` として報告します。
- 変更は `~/.ssh/ssh-ui/journal/` に予定を記録し、全ファイルを一時ファイルへ書き出して fsync した後に atomic rename します。中断した場合は `~/.ssh/ssh-ui/backups/<id>/` の世代バックアップから復旧するか、staged 内容で完了させるかを選べます。
- 完了した変更は `~/.ssh/ssh-ui/history/` に記録します。バックアップは自動削除しません。
- 複数ファイルの OS レベル完全 atomic commit は存在しないため、部分適用は隠さず pending として提示します。
- ディレクトリ構成要素の入れ替えに対する time-of-check/time-of-use 競合は best-effort でしか防げません。`O_NOFOLLOW` と構成要素ごとの検査を行いますが、同一ユーザー権限で動作する悪意あるプロセスからは完全には保護できません。
- このエンジンは `/api/v1/config/*` として同一オリジンの HTTP API に公開済みです。境界は次節を参照してください。

## Connections UI とグループの境界

- `~/.ssh/config` と `Include` 先を正本として編集します。フォーム編集、任意キー・値編集、ブロック Raw 編集、ファイル全体 Raw 編集はすべて同じ lossless 構文木を更新し、変更していない行は 1 バイトも書き換えません。
- 保存は必ず「読み込んだ内容」を base として送り、その SHA-256 を precondition にします。外部変更があった場合は書き込まず、三者差分を表示します。
- 保存前に再パースと Include グラフ再解決を行い、新たに壊れた行や新たな Include エラーが生じる変更は拒否します。既に存在していた問題は保存の障害にしません。
- UI 専用情報は `~/.ssh/ssh-ui/metadata.json` に保存します。スキーマバージョン、グループ、タグ、色、メモ、お気に入り、表示順のみで、鍵本文やパスフレーズは保存しません。
- Host の識別は「正規化した相対パス + 具体的な主 alias」です。改名は config と metadata を同一トランザクションで更新し、対応先が消えた metadata は推測で付け替えず orphan として再関連付けを求めます。
- ファイルとフォルダの移動・改名・削除はまだ提供していません。`storage` に journal 付きの削除・改名プリミティブが必要で、後続の `ssh-ui-file-operations` 計画で対応します。Host ブロックの別ファイルへの移動も同様に後続タスクです。
- グループは `groups.ssh-ui.conf` に通常の `Host` ブロックとして生成し、子グループを親より先に配置します。`Include` は具体的な Host ブロックの後、最初の catch-all ブロックの前に挿入します。
- ワイルドカード、否定パターン、`Match`、alias 重複によって単純な継承へ投影できない場合は、結果を捏造せず「complex external rule」として出所を表示します。
- Effective タブと Diagnostics タブは値の出所説明のみです。`ssh -G` による実効設定判定、到達性診断、Terminal 起動、鍵管理、Known Hosts は後続サブシステムで実装します。
- API は同一オリジンのみです。CORS は有効化せず、状態変更 API は `X-SSH-UI-CSRF` header を要求し、`/api/` 応答は `Cache-Control: no-store` を返します。エラー応答は安定コードと位置情報のみを含み、設定本文は返しません（利用者が解決すべき競合差分を除く）。

## 鍵管理の境界

- `~/.ssh` 配下のファイルは内容と権限で分類します。ファイル名だけで秘密鍵と断定しません。`~/.ssh/ssh-ui/`（backups、trash、journal、history）は走査対象、agent 登録対象、config 候補のいずれからも除外します。
- 通常のソフトウェア鍵（Ed25519、RSA、ECDSA）は Go プロセス内で生成・暗号化します。パスフレーズは argv にも環境変数にも載せません。
- FIDO の `ed25519-sk` と `ecdsa-sk` はハードウェアの操作が必要なため生成しません。実行すべき `ssh-keygen` コマンドだけを表示します。Terminal の起動はロードマップのサブシステム5が担当します。
- 対応アルゴリズムの一覧は `ssh -F /dev/null -Q key` で取得します。これは設定ファイルを読まず `Match exec` も評価しないため、サブシステム5が担当する `ssh -G` の実効設定判定とは別物です。取得できない場合は Ed25519 のみの fallback を提示し、その旨を明示します。
- パスフレーズ変更は既存の秘密鍵を置き換えるため、世代バックアップを意図的に作りません。鍵本文の複製を `~/.ssh/ssh-ui/backups/` に残さないためです。中断した場合は完了のみ可能で、`Rollback` は「復旧できない」と正直に拒否します。
- 削除は `~/.ssh/ssh-ui/trash/<entry>/` への `rename` です。バイト列を複製せず、元の権限をそのまま保ちます。復元先が埋まっている、または同一 fingerprint の鍵が既に存在する場合は推測せず blocker を提示して拒否します。完全削除はバックアップを取らないため取り消せません。
- 秘密鍵の表示と完全削除は、session cookie と `X-SSH-UI-CSRF` に加えて一度限りの確認 token（`X-SSH-UI-Action`）を要求します。token は「確認ダイアログが表示していた内容」の digest に束縛されます。digest はサーバ側で発行時と使用時の両方で計算するため、確認から実行までの間に鍵が差し替わった場合、その token は無効になります。
- 秘密鍵の表示応答は `Cache-Control: no-store` で返し、鍵本文はログ行にも history にもエラー応答にも出しません。history には「表示した」という事実と対象パスのみを記録します。
- 画面は表示した鍵本文をコンポーネント状態にのみ保持し、ダイアログを閉じた時点で破棄します。`localStorage`、`sessionStorage`、グローバルオブジェクトのいずれにも書きません。再表示には新しい確認 token が必要です。
- ssh-agent と login Keychain への登録は `ssh-add` 経由です。パスフレーズは標準入力のみで渡します。`SSH_ASKPASS` と `SSH_ASKPASS_REQUIRE` が設定されていると `ssh-add` は外部プログラムにパスフレーズを尋ねてしまうため、子プロセスの環境は `HOME`、`PATH`、`LANG`、`SSH_AUTH_SOCK` のみに置き換えます。
- パスフレーズはアプリケーションでは一切保存しません。保持は利用者の明示的な操作による macOS Keychain または ssh-agent への委譲のみです。

## SSH 実行の境界

- 外部プロセスは argv を直接組み立てて実行します。シェル、`sh -c`、文字列連結した AppleScript は使いません。alias、hostname、user は OpenSSH が受理する値であっても信頼しません。
- `Match exec`、`ProxyCommand`、`KnownHostsCommand`、`LocalCommand`、`RemoteCommand` を危険ディレクティブとして構文木から検出し、実際のコマンド文字列を表示します。評価と接続のゲートは別物です。設定を読むだけで走るのは `Match exec` だけなので `ssh -G` を止めるのはこれ一つですが、接続はどの危険ディレクティブでも止まります。どちらの場合でも検出したディレクティブは必ず全て表示します。
- OpenSSH は展開したトークンをシェル向けにエスケープしません。hostname や user の値がそのまま危険ディレクティブのシェルへ届きます。UI と API はこの警告を必ず添えます。
- 接続テスト、Terminal 起動、`known_hosts` 変更、`ssh-keyscan`、公開鍵のリモート登録、危険な設定での `ssh -G` は、CSRF header に加えて、対象と操作種別と表示済みコマンドへ紐付いた一回限りの action token（`X-SSH-UI-Action`）を必要とします。digest はサーバ側で発行時と使用時の両方で計算するため、確認から実行までの間に設定を編集すると token は無効になります。
- 値の出所（provenance）は必ず実在するファイルと行を指します。ワイルドカード、否定パターン、`Match` ブロック、別名の重複などで単純に説明できない場合は「単純ではない」と印を付け、権威は `ssh -G` に委ねます。出所を推測して捏造することはありません。
- 到達性チェックは宛先を直接 dial します。`ProxyJump` と `ProxyCommand` は使いません。結果には必ずその旨を表示します。踏み台越しにしか到達できないホストがここで失敗するのは想定どおりです。
- 認証テストはタイムアウトとキャンセルを持ち、出力を上限つきで取得し、forwarding と `LocalCommand` をコマンドライン優先設定で無効化します。無効化できない実行可能ディレクティブが残る場合は、その内容を確認するまで開始しません。
- Terminal 起動は安全な文字集合の alias に限ります。それ以外はコマンドのコピーだけを提供します。AppleScript は定数で、alias は `argv` として渡すため、alias が抜け出せる AppleScript 文字列自体が存在しません。危険な alias をエスケープして通すことはせず、拒否します。
- `ssh-keyscan` の結果は本人性を証明しません。常に「未検証」と表示し、別経路で取得した fingerprint の一致か、明示的な承認がある場合だけ追加します。
- `known_hosts` の変更は `storage.Manager` を通し、journal と世代バックアップを残します。削除は表示していた行の digest を伴い、ファイルが変化していれば衝突として拒否します。解析は無損失なので、指定された行以外は 1 バイトも変わりません。
- 公開鍵のリモート登録は POSIX shell を持つ環境に限定し、固定のリモート処理へ公開鍵を標準入力で渡します。ユーザー入力をリモートシェル文字列へ補間しません。対応外環境では手順の表示だけを行います。
- OpenSSH を起動する子プロセスの環境は `HOME`、`PATH`、`LANG`、`SSH_AUTH_SOCK` のみに置き換えます。`SSH_ASKPASS` が設定されていると `ssh` がパスフレーズを外部プログラムに尋ね、非対話であるはずの検査がダイアログ待ちになるためです。
- 応答に載せる `ssh` の出力は上限つきで、ホームディレクトリのパスを `~` に置換してから返します。利用者のアカウント名を応答本文へ持ち出さないためです。
- 自動テストは実リモート、実 `~/.ssh`、実 Keychain、実 Terminal を使いません。唯一の例外は、一時ディレクトリ内の安全な fixture に対する `ssh -G -F` の差分試験です。`ssh` が無い環境では skip します。

## 強化とリリースの境界

- リクエスト本文には二段の上限があります。middleware の `MaxRequestBodyCeiling`（2 MiB）が全 `/api/` 要求の天井で、各ハンドラーはさらに小さい上限を持ちます。宣言された `Content-Length` が天井を超える要求はハンドラーへ届く前に 413 で拒否し、長さを宣言しない chunked 要求は読み取り自体を天井で打ち切ります。本文を読まないルート（`/api/v1/diagnostics/config` や `/api/v1/keys/{keyId}/trash`）にも同じ天井が掛かるのは前者のためです。
- 外部コマンドの出力は `platform.MaxCapturedOutput`（64 KiB）で打ち切られます。打ち切られた `ssh -G` 出力は解析せず、部分的な実効値として返しません。認証テストの stderr は `MaxReportedOutput`（8 KiB）までに制限して表示します。
- `make fuzz` は `FUZZ_TARGETS` に列挙した全 target を順に実行します。`go test -fuzz` は一度に 1 target しか動かせないため、1 行で書くと最初の target しか回りません。target を追加して一覧に加え忘れると `TestMakefileFuzzTargetsCoverEveryFuzzFunction` が失敗します。
- fuzz の対象は、設定パーサーのラウンドトリップ、Include パターン展開、`known_hosts` リーダー、`ssh -G` 出力パーサー、HTTP リクエストデコーダーの 5 つです。いずれも実 fixture を seed にしています。
- `./bin/ssh-ui -open=false` は既定ブラウザを開かず、bootstrap fragment 付き URL を標準出力へ 1 行だけ出します。自動化用の明示的なオプションであり、通常の利用では使いません。token は `open <url>` の argv と同程度の露出であり、それ以上ではありません。
- 配布物は UI を埋め込んだ単一バイナリです。`otool -L` はシステムライブラリのみを表示し、同梱ランタイムはありません。`make e2e` は毎回ビルドし直した実バイナリを Playwright で駆動するため、埋め込み済み UI が古いままだと E2E が失敗します。
- `make verify-generated` は `api/openapi.yaml` から Go と TypeScript の型を再生成し、コミット済みの生成物と一致しなければ失敗します。生成物を手で編集してはいけません。
