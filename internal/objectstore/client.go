// Package objectstore は、このアプリケーションが必要とする範囲の S3 API を話す。
//
// 中身は aws-sdk-go-v2 である。以前はここに手書きの SigV4 署名器と、path-style で
// URL を組み立てるだけのリクエスト構築があった。読み切れる大きさではあったが、
// S3 互換ストアごとの差や署名仕様の変更を自前で持ち続ける理由はないため、SDK に
// それらを任せている。既存設定との互換性のため、アドレッシングは path-style の
// ままである。
//
// このパッケージが残っているのは、SDK が面倒を見ない性質がいくつかあるからである。
// エンドポイントはループバックでない限り https であること、本文には必ず上限が
// あること、そしてストアの拒否理由がこのアプリケーションの語彙へ畳まれ、S3 の
// エラードキュメントが呼び出し側へ漏れないこと。
package objectstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
)

var (
	// ErrPreconditionFailed は、最後に読んだあとにオブジェクトが変化したことを報告
	// する。compare-and-swap の失敗であり、それこそがこのクライアントの存在意義で
	// ある。「auto」同期が他のマシンを踏み潰さないのは、これによる。
	ErrPreconditionFailed = errors.New("the object changed since it was last read")
	// ErrNotFound は、そのキーの下にオブジェクトが存在しないことを報告する。
	ErrNotFound = errors.New("no object under that key")
	// ErrRefused は、それ以外の拒否をすべて報告する。本文は持ち回らない。S3 の
	// エラードキュメントはバケット名とリクエスト ID を名指しするが、どちらもこの
	// アプリケーションが表示するメッセージに入れてよいものではない。
	ErrRefused = errors.New("the object store refused the request")
	// ErrBothConditions は、If-Match と If-None-Match を同時に設定した呼び出しを
	// 拒否する。これはプログラミングの誤りであり、リクエストを送る前に捕まえる。
	ErrBothConditions = errors.New("If-Match and If-None-Match are mutually exclusive")
	// ErrObjectTooLarge は、単一リクエストの上限を超える本文を拒否する。
	ErrObjectTooLarge = errors.New("the object is too large for a single request")
	// sharedDefaultHTTPClient は、操作ごとに SDK クライアントを組み立てても接続プールを
	// 共有する。資格情報やエンドポイントは HTTP クライアントには保持されない。
	sharedDefaultHTTPClient = awshttp.NewBuildableClient().WithTimeout(defaultRequestTimeout)
)

// MaxObjectBytes は、このクライアントが送受信する最大のスナップショットサイズ。
//
// S3 は 1 回の PUT で 5 GiB を許すが、これはそれよりはるかに小さい。~/.ssh は
// キロバイト単位であり、この上限に近づくというのは、誰かの設定が大きいという
// ことではなく、何かがおかしいということだからだ。
const (
	MaxObjectBytes        = 256 << 20
	defaultRequestTimeout = 60 * time.Second
)

// Credentials はアクセスキーの組。ログに出ることはなく、URL に現れることもない。
// このクライアントはヘッダーだけで署名する。presign は使わない。
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

// Object は、取得したオブジェクトとその entity tag。
type Object struct {
	Body []byte
	// ETag は、このバージョンそのものを識別する。あとで条件付き書き込みを行う際の
	// 比較対象であり、このクライアントがリモートについて覚えている唯一のもので
	// ある。
	ETag string
}

// Client は、このアプリケーションが必要とする範囲の S3 API を話す。
type Client struct {
	HTTP *http.Client
	// RequestTimeout はリクエスト全体の上限。0 なら 60 秒である。テストや、明示的に
	// より短い上限を必要とする呼び出し側だけが設定する。
	RequestTimeout time.Duration
	// Endpoint はアカウントのエンドポイント。たとえば
	// https://<account>.r2.cloudflarestorage.com。https でなければならない。
	Endpoint string
	Bucket   string
	// Region は R2 では "auto"。本物の AWS ではバケットのリージョンでなければ
	// ならない。署名スコープに入るので、食い違えばストアが拒否する。
	Region string
	Creds  Credentials
}

// ErrInsecureEndpoint は、ループバックでない平文のエンドポイントを拒否する。
// 本文はここへ届く前に暗号化されているが、資格情報はそうではない。回線から
// 拾った署名を再生すれば、そのクロックスキューの窓が閉じるまでは有効な
// リクエストである。
var ErrInsecureEndpoint = errors.New("the object store endpoint must be https unless it is loopback")

// loopbackHosts は、平文の http で到達してよいホスト。
//
// これがあるのは、このクライアントを本物の S3 実装 — このマシン上の SeaweedFS か
// MinIO、あるいは CI のサービスコンテナ — に対して動かせるようにするためである。
// 本物のサーバーが条件付き PUT に何をするかを知る方法は、それしかない。
// ループバック接続はマシンの外からは観測できないので、そこには TLS が守るものが
// ない。それ以外はすべて https でなければならない。
//
// "localhost" を含めているのは、CI のサービスコンテナへそう到達するからである。
// リテラルではなく名前なので、原理的には別の場所へ解決されうる。この例外は、本文が
// すでに暗号文であるリクエストの平文トランスポートに限定されており、そうしない
// 場合の代案は、統合テストの網羅をまったく持たないことである。
var loopbackHosts = map[string]bool{"127.0.0.1": true, "::1": true, "localhost": true}

// api は、この呼び出しのために構成された SDK のクライアントを返す。
//
// LoadDefaultConfig は通らない。あれは環境変数・共有プロファイル・SSO・そして
// インスタンスメタデータの順に資格情報を探しに行くもので、そのうちひとつは
// ネットワークへ手を伸ばす。ここで欲しいのは利用者が入力した鍵ひとつだけなので、
// 静的なプロバイダを直接渡す。これにより、このアプリケーションが自分以外へ通信する
// のは更新確認だけ、という性質が保たれる。
func (c Client) api() (*s3.Client, error) {
	if err := c.checkEndpoint(); err != nil {
		return nil, err
	}
	options := s3.Options{
		Region:       c.Region,
		BaseEndpoint: aws.String(c.Endpoint),
		// path-style は https://<endpoint>/<bucket>/<key> で、R2・MinIO・SeaweedFS と
		// 既存の AWS S3 設定が受け付ける形である。ここを暗黙に変えると、利用中の
		// カスタムエンドポイントのホスト名と TLS 証明書を壊すため固定している。
		UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider(
			c.Creds.AccessKeyID, c.Creds.SecretAccessKey, ""),
		// 既定では、送るものごとに CRC32 を計算して aws-chunked のトレーラーで
		// 送る。本文はここへ届く前に封をされており、その中身は AEAD のタグが
		// 守っている。転送の破損は署名が捕まえる。要求されたときだけ計算させて、
		// 回線に載るものを単純に保つ。
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		APIOptions:                 []func(*middleware.Stack) error{signThePayload},
		HTTPClient:                 c.httpClient(),
	}
	return s3.New(options), nil
}

// httpClient は、接続後に応答を止めるストアにもリクエスト全体の上限を適用する。
// 非 2xx の本文は、SDK が XML としてメモリへ全量コピーする前に捨てる。この
// アプリケーションが拒否の分類に使うのはステータスコードだけであり、本文を
// 読ませる理由はない。
func (c Client) httpClient() aws.HTTPClient {
	timeout := c.RequestTimeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}

	var base aws.HTTPClient
	if c.HTTP == nil {
		base = sharedDefaultHTTPClient
		if c.RequestTimeout > 0 {
			base = awshttp.NewBuildableClient().WithTimeout(timeout)
		}
	} else {
		client := *c.HTTP
		if c.RequestTimeout > 0 || client.Timeout <= 0 {
			client.Timeout = timeout
		}
		base = &client
	}
	return discardErrorBodyClient{base: base}
}

type discardErrorBodyClient struct {
	base aws.HTTPClient
}

func (c discardErrorBodyClient) Do(request *http.Request) (*http.Response, error) {
	response, err := c.base.Do(request)
	if err != nil || response == nil || response.StatusCode < http.StatusMultipleChoices || response.Body == nil {
		return response, err
	}
	_ = response.Body.Close()
	response.Body = http.NoBody
	response.ContentLength = 0
	return response, nil
}

// signThePayload は、S3 が PutObject に入れる UNSIGNED-PAYLOAD を元に戻す。
//
// SDK は HTTPS の PutObject に UseDynamicPayloadSigningMiddleware を入れる。
// 本文が seekable でなくても送れるようにするためのもので、その代償として
// X-Amz-Content-Sha256 が "UNSIGNED-PAYLOAD" になり、署名は本文を覆わなくなる。
// ここで送るものは誰かの ~/.ssh のスナップショットであり、しかも常に
// []byte なので seekable である。本文に署名することが、改変された本文を、
// 受理されるリクエストではなく拒否されるリクエストにしている。
//
// これら 3 つのミドルウェアは ID を共有しているので、Swap がそのまま入れ替えになる。
func signThePayload(stack *middleware.Stack) error {
	compute := &v4.ComputePayloadSHA256{}
	_, err := stack.Finalize.Swap(compute.ID(), compute)
	return err
}

func (c Client) checkEndpoint() error {
	parsed, err := url.Parse(c.Endpoint)
	if err != nil {
		return err
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && loopbackHosts[parsed.Hostname()] {
		return nil
	}
	return ErrInsecureEndpoint
}

func objectKey(key string) string {
	return strings.TrimPrefix(key, "/")
}

// Get は、オブジェクトとその ETag を取得する。
func (c Client) Get(ctx context.Context, key string) (Object, error) {
	api, err := c.api()
	if err != nil {
		return Object{}, err
	}
	output, err := api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.Bucket), Key: aws.String(objectKey(key)),
	})
	if err != nil {
		return Object{}, classify(err)
	}
	defer func() { _ = output.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(output.Body, MaxObjectBytes+1))
	if err != nil {
		return Object{}, err
	}
	if len(body) > MaxObjectBytes {
		return Object{}, ErrObjectTooLarge
	}
	return Object{Body: body, ETag: aws.ToString(output.ETag)}, nil
}

// Head は、本文なしで ETag を返す。
func (c Client) Head(ctx context.Context, key string) (string, error) {
	api, err := c.api()
	if err != nil {
		return "", err
	}
	output, err := api.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(c.Bucket), Key: aws.String(objectKey(key)),
	})
	if err != nil {
		return "", classify(err)
	}
	return aws.ToString(output.ETag), nil
}

// Put はオブジェクトを書き、新しい ETag を返す。
//
// ifMatch と ifNoneMatch が compare-and-swap である。このアプリケーションの
// 呼び出し側が使うのは、そのうちちょうど一方だけだ。最初の書き込みには
// If-None-Match: *、それ以降のすべての書き込みには If-Match: <最後に見た ETag>。
// 無条件の書き込みも可能だが、ここの呼び出し側は誰もそれをしない。失敗しえない
// 書き込みは、他のマシンを上書きしうる書き込みだからである。
func (c Client) Put(ctx context.Context, key string, body []byte, ifMatch, ifNoneMatch string) (string, error) {
	if ifMatch != "" && ifNoneMatch != "" {
		return "", ErrBothConditions
	}
	if len(body) > MaxObjectBytes {
		return "", ErrObjectTooLarge
	}
	api, err := c.api()
	if err != nil {
		return "", err
	}
	input := &s3.PutObjectInput{
		Bucket:        aws.String(c.Bucket),
		Key:           aws.String(objectKey(key)),
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
		ContentType:   aws.String("application/octet-stream"),
	}
	if ifMatch != "" {
		input.IfMatch = aws.String(ifMatch)
	}
	if ifNoneMatch != "" {
		input.IfNoneMatch = aws.String(ifNoneMatch)
	}
	output, err := api.PutObject(ctx, input)
	if err != nil {
		return "", classify(err)
	}
	return aws.ToString(output.ETag), nil
}

// classify は、ストアの答えをこのアプリケーションの語彙へ畳む。
//
// レスポンスを伴わないエラー — 接続の拒否、名前解決の失敗、タイムアウト — は
// そのまま返す。S3 のエラードキュメントを含みようがないからだ。レスポンスを
// 伴うものは番兵へ写し、本文はここで捨てる。SDK のエラーはストアが述べた
// メッセージを持っており、それはバケット名とリクエスト ID を名指しする。
func classify(err error) error {
	var response *awshttp.ResponseError
	if !errors.As(err, &response) {
		return err
	}
	switch response.HTTPStatusCode() {
	case http.StatusNotFound:
		return ErrNotFound
	// 412 は、If-Match または If-None-Match の失敗に対する文書化された答え。
	// 409 をここに入れているのは、衝突する書き込みを直列化するストアが代わりに
	// これを返すことがあるからで、呼び出し側にとって両者の意味は同じ。すなわち、
	// 誰かが先に到達した、ということである。
	case http.StatusPreconditionFailed, http.StatusConflict:
		return ErrPreconditionFailed
	default:
		return ErrRefused
	}
}
