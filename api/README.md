# API 契約の生成

`openapi.yaml` は、固定している `oapi-codegen v2.7.0` が正式に扱う OpenAPI 3.0.3
を使う。以前は 3.1.0 を名乗りながら、ジェネレータが未対応警告を出す基本的な
部分集合だけを使っていた。契約が使っていた `const` は同じ意味の単一要素 `enum`
へ置き換え、生成される Go と TypeScript の型を変えずに、入力とツールの対応範囲を
一致させた。

契約の生成と検証は次のコマンドで行う。

```sh
go generate ./internal/api
npm run generate:api --prefix web
go test ./internal/api -count=1
npm run typecheck --prefix web
```

OpenAPI 3.1 でしか使えない機能を追加する場合は、先にジェネレータの正式対応を
確認し、生成結果を両言語で比較してから契約のバージョンを上げること。

## 生成される命名規則

oapi-codegen v2.7.0 は camelCase のプロパティを、先頭の 1 文字だけを大文字にした
Go の PascalCase として出力する。したがって `id` は `Id`、`keyId` は `KeyId`、
`transactionId` は `TransactionId` になる — `ID` ではない。手書きのコードは
`models.gen.go` を編集するのではなく、ジェネレータに合わせること。あのファイルは
再生成される。`required` に入っていないプロパティは `omitempty` 付きのポインタに
なる。`Problem.Detail` が `*string` で、`KeyItem.Certificate` が
`*KeyCertificate` なのはそのためである。

## 鍵 vault の契約に関する決定

- タイムスタンプは `format: date-time` ではなく、RFC 3339 形式の素の
  `type: string` である。値は API 境界で検証し、生成される両言語の型を string と
  して予測可能に保つ。
- `kind`、`algorithm`、アクションの `kind` といった値の集合は `enum` ではなく素の
  文字列とし、API の境界において Go の実行時に検証する。型の生成が入力に対する
  唯一の検査であってはならない。
- `Problem.detail` は、`ssh-add` の stderr のような、上限付きでホームパスを浄化
  したメッセージを運ぶ。鍵素材、パスフレーズ、トークン、絶対パスを含んでは
  ならない。
- `KeyCertificate.validBefore` は符号付き整数と `neverExpires` フラグの組である。
  OpenSSH は「無期限」を 2^64-1 と綴るが、それは符号付き整数に収まらない。そこで
  その場合は、負の数へ折り返すのではなく、`neverExpires: true` と境界値 0 として
  報告する。
- `POST /api/v1/keys/hardware-command` はディスク上の何も変更しない。POST に
  してあるのは、検証済みの JSON 本文を運ぶためであり、また GET 以外のすべての
  リクエストと同じく CSRF の要求対象に含めるためである。
- `IssueActionRequest` が運ぶのは `kind` と `target` だけであり、トークンが束縛
  される evidence を運ぶことは決してない。サーバーは、確認ダイアログが表示して
  いた内容 — 秘密鍵のパス・フィンガープリント・内容のダイジェスト、あるいは
  ごみ箱エントリに列挙された内容 — から、発行時と使用時の両方で evidence を
  導出する。自前の evidence を渡せる呼び出し側は、一度も表示されていない状態に
  トークンを束縛できてしまう。この束縛は、まさにそれを防ぐために存在する。
- アクションの `kind` の値は、`internal/session` の共有定数
  `private_key.reveal` と `trash.purge` である。`domain.verb` と綴るのは、操作を
  確認するすべてのサブシステムの語彙を session パッケージが所有しているからで
  ある。
