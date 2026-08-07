# sshc 設計

作成日: 2026-08-04  
状態: ユーザー承認済み設計の文書化

## 1. 目的

`sshc` は、macOS 上の OpenSSH クライアント設定と鍵を localhost の Web UI から整理・編集・検証するツールである。既存の `~/.ssh/config` と `Include` 先を正本として扱い、通常の Terminal からの `ssh <alias>`、`scp`、`rsync` と完全に共存する。

主な利用目的は以下である。

- 既存の SSH config をコメントや記述順を壊さず整理する
- `Include` を利用して設定ファイルを階層化する
- Home Servers などのグループへ共通設定を持たせる
- 鍵の生成、確認、コピー、agent 登録、削除、復元を行う
- `ProxyJump` を含む接続経路を設定・確認する
- 実効設定、到達性、認証状態を診断する
- UI から macOS Terminal を開いて通常の SSH 接続を開始する

## 2. 初期対応範囲

### 2.1 対応環境

- クライアント OS は macOS のみ
- OpenSSH は OS にインストール済みのものを利用
- サーバーは `127.0.0.1` のみで待ち受ける
- `sshc` コマンドの実行中だけ動作し、常駐 LaunchAgent は作らない
- UI は React、Vite、TypeScript、Tailwind CSS
- API は Go と Echo
- 配布物はフロントエンドを埋め込んだ単一 Go バイナリを目標とする

### 2.2 将来対応

Linux と Windows を後から追加できるよう、実在する OS 差分だけを Platform interface に分離する。初期版では未検証の OS 実装や、Unix の権限モデルを Windows ACL に見せかける抽象化は作らない。

### 2.3 初期版で行わないこと

- ブラウザ内蔵 SSH ターミナル
- LAN や Tailnet からのアクセス
- 複数ユーザー・共有サーバー運用
- クラウド同期
- アプリ独自形式を SSH 設定の正本にすること
- `~/.ssh` 外のファイルの編集
- 実サーバーを使う無人 E2E テスト

## 3. 技術方式

採用方式は Go + Echo + React/Vite/Tailwind CSS とする。Express を採用しない理由は、TypeScript だけでは HTTP 入力の実行時検証が得られず、Node ランタイムと依存関係を配布時に追加する一方、このツールではファイル権限、アトミック更新、プロセス制御、単一バイナリ化の価値が大きいためである。

OpenAPI を API 契約の正本とし、Go の入出力型と TypeScript クライアント型を生成する。型生成だけに依存せず、API 境界で実行時入力検証を行う。

## 4. アーキテクチャ

```text
sshc CLI
├── Echo HTTP API
├── embedded React application
├── application use cases
├── lossless SSH config engine
├── filesystem transaction manager
├── key manager
└── Platform interface
    └── macOS adapter
```

### 4.1 パッケージ境界

- `domain`: Host、Group、Key、Include、Tag、履歴などの OS 非依存モデル
- `config`: lossless 構文木、Include グラフ、フォーム投影、Raw 編集
- `application`: 作成、編集、移動、削除、検証、接続テストなどのユースケース
- `storage`: metadata、履歴、隔離領域、ファイルトランザクション
- `platform`: Keychain、ssh-agent、Terminal、OpenSSH 探索、権限操作
- `http`: Echo handler、セッション、OpenAPI 入出力
- `frontend`: React UI と生成済み API クライアント

各境界は interface で差し替え可能にし、テストでは実ファイル、実 Keychain、実 Terminal、実リモート接続を使用しない。

### 4.2 正本

- 接続設定: `~/.ssh/config` とその `Include` 先
- 鍵: `~/.ssh` 配下の実ファイル
- UI 専用情報: `~/.ssh/sshc/metadata.json`

metadata にはスキーマバージョン、グループの表示情報、タグ、色、メモ、お気に入り、表示順を保存する。グループ所属は保存しない。秘密鍵本文、公開鍵本文、パスフレーズ、Keychain の秘密値は保存しない。

グループの正本は二つに分かれる。どのグループが存在し、どの順で読まれるかは `~/.ssh/config` の生成領域にある `Include` 行が正本であり、ある Host がどのグループに属するかは `~/.ssh/connections/` 配下のどのディレクトリにあるかが正本である。どちらも通常の OpenSSH 設定とディレクトリであり、metadata ではない。

Host の UI 識別は、正規化済みファイルパスと具体的な主 Host alias の組で行う。UI 経由の改名時は metadata も同一トランザクションで更新する。外部編集によって対応先が消えた場合は推測で別 Host に付け替えず、orphan として再関連付けを求める。

## 5. SSH config エンジン

### 5.1 Lossless 編集

パーサーは意味モデルだけでなく、コメント、空行、インデント、引用形式、`key value` と `key=value` の違い、未知のディレクティブ、元の改行を保持する。無変更の parse/render は byte-for-byte で元ファイルと一致しなければならない。

フォーム編集、キー・値編集、Raw 編集は同じ構文モデルを更新する。Raw が一時的に不正な場合、ブラウザ内の編集内容は保持するがディスク保存は許可しない。

### 5.2 完全設定エディタ

以下の三段階を同時に提供する。

- 一般項目専用フォーム: `Host`、`Hostname`、`User`、`Port`、`IdentityFile`、`ProxyJump` など
- 任意ディレクティブの構造化キー・値編集
- ブロック単位およびファイル全体の Raw 編集

未知または将来追加されたディレクティブも Raw 編集でき、UI が理解できないことを理由に削除・再整形しない。

### 5.3 Include グラフ

`~/.ssh/config` を起点に `Include` を解決し、ファイルツリーと参照グラフを表示する。glob は OpenSSH と同じく辞書順として扱う。循環、参照切れ、重複読み込み、`Host` または `Match` 内の条件付き Include を識別する。

`~/.ssh` 外の Include は読み取りとグラフ表示のみ許可する。外部パス、シンボリックリンク先、`../` を利用して編集 API の許可範囲を拡張しない。

### 5.4 グループ

各 Host は設定を継承するプライマリグループを一つだけ持つ。ファイルは一つのディレクトリにしか置けないため、この制約はファイルシステムが保証する。グループ名は `connections/` からの相対ディレクトリパスであり、親子階層はパスそのものが表す。複数タグは metadata 上の整理情報として設定に影響させない。

ユーザーには次の優先順位として表示する。

1. 個別 Host
2. 子グループ
3. 親グループ
4. グローバル既定値

OpenSSH は原則として先に得た値を採用するため、ファイル上では具体的な Host と子グループを先に、一般的な既定値を後に配置する。グループ共通設定はメンバーの具体的な alias を列挙する標準 `Host` ブロックとして表現し、独自ランタイムを必要としない。UI は必要な Include 順とブロック順を生成し、変更前後の実効値差分を表示する。

同じ alias の既存定義、ワイルドカード、否定パターン、`Match` によって単純な継承へ投影できない場合は、結果を捏造せず「複雑な外部ルール」として出所を表示する。

グループごとに `Include` を 1 行ずつ生成する。単一のワイルドカードにしないのは、`*` が `/` を跨がないため入れ子グループに届かず、また読み込み順が glob の辞書順に決まってしまい優先順位が偶然になるためである。生成領域は二つのマーカーコメントで囲み、その外側は 1 バイトも変更しない。挿入位置によって優先順位が変わりうる場合（catch-all が先頭にある、既存の `Include` がすでに `connections/` に到達している、マーカーが片方だけ残っている）は、自動で挿入せず拒否して理由を返す。

### 5.5 実効設定

独自エンジンは説明用の出所追跡を行うが、最終的な実効値はインストール済み OpenSSH の `ssh -G` を基準とする。ただし、評価中にコマンドを実行し得る設定では自動実行しない。詳細はセキュリティ節に定める。

## 6. 機能設計

### 6.1 Connections

- Include 階層、グループ、Host のツリー表示
- Host の作成、編集、複製、改名、移動、削除
- タグ、検索、お気に入り
- Basic、Jump、Advanced、Raw、Effective、Diagnostics の各タブ
- 単一およびカンマ区切りの多段 `ProxyJump`
- 接続経路と値の出所の可視化
- コマンドコピー、接続テスト、macOS Terminal 起動

### 6.2 Config Explorer

- Include のファイルツリーと参照グラフ
- `~/.ssh` 内のファイル作成と、グループディレクトリ間のファイル移動、グループの改名。ディレクトリの作成は行うが journal の外で行うため、中断すると空ディレクトリが残る。ディレクトリの削除と改名は journal 付きプリミティブが無く、まだ行わない
- ファイル全体の Raw 編集
- 保存前差分
- Include 循環、参照切れ、順序変更、Host 競合の診断

### 6.3 Keys

`~/.ssh` 配下を走査し、秘密鍵、公開鍵、OpenSSH 証明書、その他のファイルを内容と権限から分類する。ファイル名だけで秘密鍵と断定しない。

- Ed25519 を既定とした鍵生成
- インストール済み OpenSSH と実装が対応する RSA、ECDSA、FIDO 系の選択肢
- fingerprint、暗号化状態、権限、参照 Host の表示
- 公開鍵コピー
- 明示確認付きの秘密鍵表示・コピー
- パスフレーズ変更
- ssh-agent および macOS Keychain 登録
- ソフトデリート、復元、完全削除
- POSIX リモート環境の `authorized_keys` への公開鍵登録

通常のソフトウェア鍵は Go プロセス内で生成・暗号化し、パスフレーズを argv や環境変数に載せない。FIDO などハードウェアや対話が必要な方式は Terminal の `ssh-keygen` へ引き渡す。

パスフレーズは生成・変更処理中だけ保持し、アプリ自身では保存しない。保持を選んだ場合は macOS Keychain／ssh-agent へ明示操作で委ねる。Go の GC 上、メモリからの完全消去は保証せず、短時間保持と best-effort の上書きを行う。

秘密鍵表示 API は通常の詳細 API と分離し、毎回の確認と一回限りの reveal token を必要とする。レスポンスは `Cache-Control: no-store` とし、フロントエンドでは永続ストレージ、グローバル状態、ログ、分析イベントへ渡さない。ダイアログ終了時に参照を破棄する。ただしブラウザ拡張やクリップボード履歴まで防げるとは表示しない。

### 6.4 Known Hosts

- `known_hosts` の検索と表示
- hostname、key type、fingerprint の表示
- 古いまたは変更されたエントリーの削除
- `ssh-keyscan` による候補取得

`ssh-keyscan` の結果は本人性を証明しないため「未検証」と表示し、自動で信頼済みにしない。追加前に別経路で確認した fingerprint の入力または明示承認を求める。

### 6.5 Diagnostics と Terminal

診断を次の独立操作に分ける。

- 構文と Include グラフの検査
- 安全に評価できる場合の `ssh -G`
- ProxyJump を考慮しない直接 TCP 到達性
- 明示操作による SSH 認証テスト

SSH 認証テストではタイムアウト、キャンセル、出力上限を設ける。コマンドライン優先設定で forwarding と `LocalCommand` を無効化し、無効化できない実行可能ディレクティブが残る場合はテストを開始しない。`Match exec`、`ProxyCommand`、`KnownHostsCommand` など接続に必要な実行可能ディレクティブを利用する場合は、実行内容を表示して取得した action token があるときだけ開始する。

Terminal 起動へ渡せる Host alias は安全な文字集合に限定する。Raw 設定として OpenSSH が受理してもオプション注入や AppleScript 文字列注入の可能性がある alias は、コマンドコピーだけを許可して自動起動しない。

### 6.6 公開鍵のリモート登録

公開鍵登録は外部状態を変更する独立操作である。対象 alias、実効ユーザー、公開鍵 fingerprint、予定する変更を表示し、ユーザー確認後のみ実行する。

初期版の自動登録は POSIX shell を利用できるリモート環境に限定する。固定されたリモート処理へ公開鍵を標準入力で渡し、ユーザー入力をリモートシェル文字列へ直接補間しない。既存行との完全一致で重複を避け、`~/.ssh` と `authorized_keys` の権限を厳格にする。対応外環境では安全な手動手順だけを表示する。

### 6.7 History & Trash

- config、Include 先、metadata、`known_hosts` は UI による変更前に世代スナップショットを作成
- 履歴には時刻、対象、操作種別、内容を含まない秘密鍵 reveal の監査事実を記録
- 鍵削除は `~/.ssh/sshc/trash/` への同一ファイルシステム内移動
- trash は `0700`、鍵は元の厳格な権限を維持
- 30 日経過を表示するが自動削除しない
- 完全削除は再確認を必要とする
- 復元時は同名ファイルと config 参照の競合を確認
- backup と trash は通常の鍵走査、agent 登録、config 候補から除外

## 7. ファイルトランザクション

書き込みは以下の順序で行う。

1. 読み込み時の SHA-256 と更新情報を再確認
2. 外部変更時は処理を止めて三者差分を作成
3. 同じディレクトリの一時ファイルへ変更案を書き出す
4. 構文、Include、パス、権限、metadata の整合性を検査
5. 許可された場合のみ OpenSSH の実効設定検査を行う
6. 世代バックアップを作成
7. ファイルを flush し、同一ファイルシステム上で atomic rename
8. ディレクトリを同期し、metadata を同一論理トランザクションで更新

複数ファイルの OS レベル完全 atomic commit はできないため、journal に予定操作と完了位置を記録する。起動時に未完了 journal を検出し、元スナップショットへの復旧または完了を選べるようにする。障害時に部分更新を正常状態として隠さない。

config と metadata は原則 `0600`、管理ディレクトリは `0700` とする。既存ファイルのより厳格な権限は緩和しない。シンボリックリンクは表示するが編集時には追跡せず、time-of-check/time-of-use の差し替えも拒否する。

## 8. localhost セキュリティ

localhost は OS 完全侵害と同一ではなく、悪意ある Web サイト、ブラウザ拡張、XSS、DNS rebinding、CSRF、クリップボード履歴を別の脅威として扱う。

### 8.1 起動セッション

- `127.0.0.1` の OS 割り当てランダムポートだけで待ち受ける
- 256-bit の暗号学的乱数 bootstrap token
- token は URL fragment で UI に渡し、一度だけ HttpOnly・SameSite セッションへ交換
- 交換後は fragment を履歴から除去し、bootstrap token の再利用を拒否
- セッションはプロセスメモリだけに保持し、プロセス終了で失効
- `Host`、`Origin`、Fetch Metadata を完全一致で検証
- CORS を有効化しない
- リクエスト本文とコマンド出力に上限を設定

localhost HTTP は暗号化されないため、loopback 以外には絶対に bind しない。将来ネットワーク公開する場合は、この設計を流用せず TLS と別の認証設計を必須とする。

### 8.2 ブラウザ

- `default-src 'self'` を基礎とする厳格な CSP
- 外部 CDN、フォント、分析、telemetry を使用しない
- 秘密値を URL、ログ、例外、React 永続状態へ含めない
- 秘密鍵 API と一般 API を分離
- bootstrap 交換時にセッション専用 CSRF token を発行し、状態変更 API では `X-SSHC-CSRF` header として要求
- 秘密鍵 reveal、完全削除、接続テスト、公開鍵登録には、対象と操作種別へ紐付いた一回限り・短時間有効の action token を追加で要求

### 8.3 実行可能な SSH 設定

以下を危険ディレクティブとして識別する。

- `Match exec`
- `ProxyCommand`
- `KnownHostsCommand`
- `LocalCommand`
- `RemoteCommand`

`Match exec` は設定評価だけでもユーザーのシェルを実行し得るため、存在する対象へ `ssh -G` を自動実行しない。OpenSSH がトークンをシェル向けに自動エスケープしないことも警告する。危険ディレクティブを編集・保存すること自体は許可するが、評価または接続前に具体的なコマンドと影響を表示して別途確認する。

## 9. エラー処理

エラーは以下に分類し、秘密を除いた具体的な復旧方法を返す。

- 構文エラー: 行・列・近傍を表示し保存を拒否
- 競合: ベース、外部変更、UI 変更の三者差分
- 権限・パス: 期待値と実値を表示し、自動緩和は確認制
- OpenSSH 実行: exit code、上限内 stderr、危険実行の有無
- ネットワーク: DNS、TCP、host key、認証を区別
- リモート拒否: ローカル設定エラーとサーバー拒否を区別
- トランザクション: journal と利用可能な復旧手順を表示

ログには request body、Authorization、cookie、鍵本文、パスフレーズ、クリップボード内容を記録しない。ファイルパスと hostname も通常ログでは必要最小限にし、詳細診断ログは明示操作で短時間だけ有効にする。

## 10. テスト戦略

### 10.1 隔離

自動テストは実際の `~/.ssh`、Keychain、ssh-agent、Terminal、実サーバーを使用しない。Filesystem、CommandRunner、CredentialStore、Agent、TerminalLauncher を差し替え、テスト専用ディレクトリと fake を利用する。

### 10.2 Config

- golden fixture による byte-for-byte round trip
- コメント、空行、引用、`=`、複数値、未知項目
- `Host`、`Match`、否定、wildcard、条件付き Include
- glob 順、Include 循環、参照切れ、外部パス
- グループ継承と first-value-wins
- Raw とフォームの相互変換
- parser fuzz test
- 安全な fixture に限定した `ssh -G -F` との差分試験

### 10.3 Storage と鍵

- 各トランザクション段階への障害注入
- 保存中の外部変更
- 権限不正、容量不足、rename 失敗
- symlink 差し替えと path traversal
- 同名鍵、復元競合、未完了 journal
- Ed25519 などの生成、暗号化、再読込、fingerprint
- trash、復元、完全削除
- ログとエラーへの秘密混入検査

### 10.4 API とセキュリティ

- 不正 Host、Origin、cross-site リクエスト
- bootstrap token 再利用
- セッションなし reveal
- action token の目的外利用
- option、shell、AppleScript injection
- リクエストと出力上限
- `Cache-Control: no-store`
- CSP と外部リソース禁止
- 危険ディレクティブの暗黙実行防止

### 10.5 Frontend と E2E

- フォームと Raw の双方向同期
- パースエラー中の編集保持
- 三者差分と復旧表示
- 継承値と出所
- secret dialog 終了時の状態破棄
- Include ツリー、接続経路、履歴、trash
- API エラー分類
- 隔離環境での Playwright 主要フロー

Go 側では race detector を実行する。実リモートへの接続、`authorized_keys` 書き換え、実 Keychain、Terminal 起動は自動テストせず、明示的な手動受け入れ試験に分離する。

## 11. 実装マイルストーン

1. CLI、localhost セッション、OpenAPI、React shell、Platform interface
2. lossless config parser、Include graph、Raw editor、transaction manager
3. Host フォーム、グループ継承、metadata、差分と履歴
4. Key inventory、生成、reveal、agent／Keychain、trash
5. Diagnostics、ProxyJump 可視化、Terminal、Known Hosts、公開鍵登録
6. セキュリティ強化、fuzz、E2E、単一バイナリ化、受け入れ試験

各マイルストーンは前段の自動テストが成功し、実 `~/.ssh` を使わないデモが可能になってから次へ進む。

## 12. 完成条件

- 既存 fixture を無変更で読み書きして byte-for-byte 一致する
- 一般的な項目はフォーム、すべての項目は Raw で編集できる
- コメント、未知ディレクティブ、Include 構造を保持する
- Include 階層、単一プライマリグループ、親子継承が機能する
- 多段 ProxyJump と値の出所を表示できる
- 鍵生成、公開鍵コピー、秘密鍵 reveal、agent 登録、隔離、復元が機能する
- config 変更前に差分、保存前にバックアップを確認できる
- 外部変更と部分失敗で既存設定を黙って破壊しない
- 接続テスト、Terminal 起動、Known Hosts、公開鍵登録が明示操作で機能する
- localhost API が token、Host、Origin、Fetch Metadata で保護される
- 危険ディレクティブを暗黙実行しない
- バックエンド、フロントエンド、セキュリティ、race、E2E テストが成功する

## 13. 既知の制約と批判への回答

### 「localhost なら秘密鍵表示は安全」ではない

OS 完全侵害時に秘密鍵を隠しても防御にならない点は正しい。一方、ブラウザ拡張、XSS、CSRF、クリップボード履歴は OS 完全侵害より低い権限でも成立するため、reveal は通常 API から分離し、明示操作と no-store を必要とする。それでもコピー機能を提供するという利便性上の判断である。

### 完全 config エディタは大きなスコープである

全ディレクティブを専用フォーム化すると OpenSSH の更新に追従できない。一般項目フォーム、任意キー・値、lossless Raw のハイブリッドにすることで「すべて編集可能」と「将来互換」を両立する。

### Include は本当の継承機構ではない

Include はその位置で別ファイルを読み込む機能であり、グループオブジェクトではない。UI のグループは標準 Host ブロックと順序へコンパイルし、保存前後の実効設定差分を提示する。複雑な既存ルールを単純な継承として誤表示しない。

### ディレクトリ規約は独自形式か

部分的にそうである。正直な答えは三つに分かれる。

**越えていない部分。** 生成物はすべて通常の OpenSSH である。`connections/` 配下のファイルは `ssh_config` であり、`Include` 行は `Include` である。グループ共通設定は従来どおり標準 `Host` ブロックへコンパイルされる。このアプリケーションを消しても配置は残り、`Include` 行は残り、`ssh web-1` は動き続ける。§6.2 は元から `~/.ssh` 内のファイル操作を認めている。

**越えている部分。** OpenSSH は `connections/work/` がグループであることを知らない。知っているのは「その位置でこれらのファイルを読む」という 1 行だけである。ディレクトリの*意味*はこのアプリケーションの規約であり、他のツールが `~/.ssh` を読んでも何の宣言も見つけられない。以前は metadata.json を消せば注釈が消えるだけだったが、いまは手作業でディレクトリを平坦化すると `Include` 行も直さない限り設定が壊れる。失敗の重さが「ラベルを失う」から「不注意な再編成で設定が壊れる」へ変わった。これを問題ないと言うのは不誠実である。

**緊張を否定せず減らす方法。** グループ集合はファイルシステムから推論しない。`~/.ssh/config` の生成領域にある `Include` 行が、通常の OpenSSH 構文で、優先順位を決める順序どおりに宣言する。`Include` 行のない `connections/` 配下のディレクトリはグループではなく、`group_not_declared` として報告するだけで手を触れない。これは重要である。`~/.ssh/keys/` はすでに持っている人がいる配置であり、たまたま存在するディレクトリからグループ所属を推論すれば他人のファイルを黙って貼り替えることになる。宣言を要求することで推測を排し、所属自体は「ファイルがどこにあるか」という事実のままにできる。`Include` の glob が実際にそれを成立させているからである。

### OS 抽象化は移植性を保証しない

Platform interface は将来実装の境界であり、Windows 対応済みという意味ではない。未検証 OS の挙動を仮定せず、macOS 実装と契約テストを先に確立する。

### アトミック更新にも限界がある

単一ファイルの rename は atomic にできるが、複数ファイルと metadata 全体を OS レベルで同時 commit することはできない。そのため journal、世代バックアップ、起動時復旧を組み合わせ、部分状態を検出可能にする。
