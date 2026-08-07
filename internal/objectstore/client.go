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
)

// MaxObjectBytes は、このクライアントが送受信する最大のスナップショットサイズ。
//
// S3 は 1 回の PUT で 5 GiB を許すが、これはそれよりはるかに小さい。~/.ssh は
// キロバイト単位であり、この上限に近づくというのは、誰かの設定が大きいという
// ことではなく、何かがおかしいということだからだ。
const MaxObjectBytes = 256 << 20

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
	// Endpoint はアカウントのエンドポイント。たとえば
	// https://<account>.r2.cloudflarestorage.com。https でなければならない。
	Endpoint string
	Bucket   string
	// Region は R2 では "auto"。
	Region string
	Creds  Credentials
	Now    func() time.Time
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

func (c Client) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

func (c Client) client() *http.Client {
	if c.HTTP == nil {
		return &http.Client{Timeout: 60 * time.Second}
	}
	return c.HTTP
}

func (c Client) objectURL(key string) (string, error) {
	parsed, err := url.Parse(c.Endpoint)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		host := parsed.Hostname()
		if parsed.Scheme != "http" || !loopbackHosts[host] {
			return "", ErrInsecureEndpoint
		}
	}
	parsed.Path = "/" + strings.Trim(c.Bucket, "/") + "/" + strings.TrimPrefix(key, "/")
	return parsed.String(), nil
}

// Get は、オブジェクトとその ETag を取得する。
func (c Client) Get(ctx context.Context, key string) (Object, error) {
	response, err := c.do(ctx, http.MethodGet, key, nil, "", "")
	if err != nil {
		return Object{}, err
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, MaxObjectBytes+1))
	if err != nil {
		return Object{}, err
	}
	if len(body) > MaxObjectBytes {
		return Object{}, ErrObjectTooLarge
	}
	return Object{Body: body, ETag: response.Header.Get("ETag")}, nil
}

// Head は、本文なしで ETag を返す。
func (c Client) Head(ctx context.Context, key string) (string, error) {
	response, err := c.do(ctx, http.MethodHead, key, nil, "", "")
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	return response.Header.Get("ETag"), nil
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
	response, err := c.do(ctx, http.MethodPut, key, body, ifMatch, ifNoneMatch)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	return response.Header.Get("ETag"), nil
}

func (c Client) do(ctx context.Context, method, key string, body []byte, ifMatch, ifNoneMatch string) (*http.Response, error) {
	target, err := c.objectURL(key)
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.ContentLength = int64(len(body))
		request.Header.Set("Content-Type", "application/octet-stream")
	}
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	if ifNoneMatch != "" {
		request.Header.Set("If-None-Match", ifNoneMatch)
	}
	if err := Sign(request, c.Creds, c.Region, "s3", body, c.now()); err != nil {
		return nil, err
	}

	response, err := c.client().Do(request)
	if err != nil {
		return nil, err
	}
	switch response.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		return response, nil
	}
	_ = response.Body.Close()
	switch response.StatusCode {
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusPreconditionFailed, http.StatusConflict:
		// 412 は、If-Match または If-None-Match の失敗に対する文書化された答え。
		// 409 をここに入れているのは、衝突する書き込みを直列化するストアが代わりに
		// これを返すことがあるからで、呼び出し側にとって両者の意味は同じ。すなわち、
		// 誰かが先に到達した、ということである。
		return nil, ErrPreconditionFailed
	default:
		return nil, ErrRefused
	}
}
