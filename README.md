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
make generate  # OpenAPI から Go/TypeScript 型を再生成
make test      # Go、race detector、Vitest、TypeScript を検証
make build     # UI を生成し bin/ssh-ui へ単一バイナリを作成
```

`./bin/ssh-ui` を起動すると、OS の既定ブラウザで一度限りの bootstrap fragment を持つ URL を開きます。Ctrl-C または SIGTERM で localhost サーバーを停止します。

## セキュリティ境界

- HTTP サーバーは IPv4 の `127.0.0.1` だけに bind します。LAN、Tailnet、コンテナ外部など、ネットワークへ公開して安全な設計ではありません。
- この foundation はまだ実際の `~/.ssh` を読みません。SSH config、鍵、Keychain、Terminal、リモートホストへアクセスする機能は含みません。
- bootstrap、session、CSRF の値をログへ出してはいけません。bootstrap は URL fragment に置き、ブラウザが直ちに履歴から除去します。
- 同一マシン上の悪意あるプロセス、侵害されたブラウザ、ブラウザ拡張から秘密を完全には保護できません。将来の秘密鍵 reveal/copy 機能でも、ブラウザ拡張やローカルのクリップボード監視・履歴ツールに対して秘密は脆弱です。
- UI は埋め込みファイルシステムからのみ配信し、URL を OS ファイルパスへ変換しません。存在しない API は SPA へフォールバックしません。
