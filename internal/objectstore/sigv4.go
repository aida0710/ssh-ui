// Package objectstore は、読み切れる程度に小さい S3 互換クライアントである。
//
// これがあるのは、このアプリケーションが新しいモジュール依存を持たないからであり、
// また、必要とする S3 API の部分が三つの動詞だけだからである。Signature Version 4
// は、このファイルが明示的に組み立てる文字列に HMAC-SHA256 を四回適用したもので、
// その全体が標準ライブラリで書ける。
package objectstore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Credentials はアクセスキーの組。ログに出ることはなく、URL に現れることもない。
// このクライアントはヘッダーだけで署名する。
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

// ErrUnsignedPayloadRefused は、このクライアントが署名しないリクエストを拒否する。
//
// S3 は UNSIGNED-PAYLOAD を許すが、このクライアントはそれを提供しない。送るものは
// すべて誰かの ~/.ssh のスナップショットである。本文に署名することが、改変された
// 本文を、受理されるリクエストではなく拒否されるリクエストにしている。
var ErrUnsignedPayloadRefused = errors.New("this client always signs the payload")

const (
	algorithm            = "AWS4-HMAC-SHA256"
	contentSHA256Header  = "X-Amz-Content-Sha256"
	dateHeader           = "X-Amz-Date"
	unsignedPayloadValue = "UNSIGNED-PAYLOAD"
	timeFormat           = "20060102T150405Z"
	dateFormat           = "20060102"
)

// Sign は、リクエストに Authorization、X-Amz-Date、X-Amz-Content-Sha256 を加える。
//
// payload は本文そのもの。nil の payload は空文字列のハッシュに署名する。これは
// GET や HEAD が持つものである。now が time.Now の呼び出しではなくパラメータなのは、
// どのテストもおおむね正しいのではなく厳密に正しくあるためだ。
func Sign(request *http.Request, credentials Credentials, region, service string, payload []byte, now time.Time) error {
	if request.Header.Get(contentSHA256Header) == unsignedPayloadValue {
		return ErrUnsignedPayloadRefused
	}
	stamp := now.UTC()
	payloadHash := hashHex(payload)

	request.Header.Set(dateHeader, stamp.Format(timeFormat))
	request.Header.Set(contentSHA256Header, payloadHash)
	if request.Host != "" {
		request.Header.Set("Host", request.Host)
	} else {
		request.Header.Set("Host", request.URL.Host)
	}

	signed, canonicalHeaders := canonicalHeaderSet(request)
	canonical := CanonicalRequest(request, canonicalHeaders, signed, payloadHash)
	scope := stamp.Format(dateFormat) + "/" + region + "/" + service + "/aws4_request"
	toSign := StringToSign(algorithm, stamp, scope, canonical)
	signature := hex.EncodeToString(signingKey(credentials.SecretAccessKey, stamp, region, service).sign(toSign))

	request.Header.Set("Authorization", algorithm+
		" Credential="+credentials.AccessKeyID+"/"+scope+
		", SignedHeaders="+signed+
		", Signature="+signature)
	return nil
}

// CanonicalRequest は正規化リクエスト文字列を組み立てる。公開されている AWS の
// テストベクタがこれを明示的に与えているためエクスポートしてある。最終署名だけを
// テストした署名器は、どこで誤ったのかを何も教えてくれない。
func CanonicalRequest(request *http.Request, canonicalHeaders, signedHeaders, payloadHash string) string {
	path := request.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	return strings.Join([]string{
		request.Method,
		path,
		canonicalQuery(request),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
}

// StringToSign は、署名の計算対象となる文字列を組み立てる。
func StringToSign(algorithmName string, stamp time.Time, scope, canonical string) string {
	return strings.Join([]string{
		algorithmName,
		stamp.UTC().Format(timeFormat),
		scope,
		hashHex([]byte(canonical)),
	}, "\n")
}

// canonicalHeaderSet は、署名対象ヘッダーの一覧と正規化ヘッダーのブロックを返す。
// リクエスト上のすべてのヘッダーに署名する。このクライアントは送るつもりのある
// ものしか設定しないので、全部に署名する方が、部分集合を選ぶより単純でもあり
// 厳しくもある。
func canonicalHeaderSet(request *http.Request) (signed, canonical string) {
	names := make([]string, 0, len(request.Header)+1)
	values := map[string]string{}
	for name, list := range request.Header {
		lowered := strings.ToLower(name)
		names = append(names, lowered)
		trimmed := make([]string, len(list))
		for index, value := range list {
			trimmed[index] = strings.Join(strings.Fields(value), " ")
		}
		values[lowered] = strings.Join(trimmed, ",")
	}
	sort.Strings(names)

	var builder strings.Builder
	for _, name := range names {
		builder.WriteString(name)
		builder.WriteString(":")
		builder.WriteString(values[name])
		builder.WriteString("\n")
	}
	return strings.Join(names, ";"), builder.String()
}

func canonicalQuery(request *http.Request) string {
	query := request.URL.Query()
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		list := query[key]
		sort.Strings(list)
		for _, value := range list {
			parts = append(parts, escape(key)+"="+escape(value))
		}
	}
	return strings.Join(parts, "&")
}

// escape は RFC 3986 の unreserved のみのパーセントエンコーディング。net/url の
// QueryEscape は空白を "+" に変えるが、SigV4 はそれを受け付けない。
func escape(value string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		if strings.IndexByte(unreserved, character) >= 0 {
			builder.WriteByte(character)
			continue
		}
		builder.WriteString("%")
		builder.WriteString(strings.ToUpper(hex.EncodeToString([]byte{character})))
	}
	return builder.String()
}

type derivedKey []byte

func (k derivedKey) sign(message string) []byte {
	mac := hmac.New(sha256.New, k)
	mac.Write([]byte(message))
	return mac.Sum(nil)
}

func signingKey(secretAccessKey string, stamp time.Time, region, service string) derivedKey {
	key := derivedKey("AWS4" + secretAccessKey)
	key = key.sign(stamp.UTC().Format(dateFormat))
	key = derivedKey(key).sign(region)
	key = derivedKey(key).sign(service)
	return derivedKey(derivedKey(key).sign("aws4_request"))
}

func hashHex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
