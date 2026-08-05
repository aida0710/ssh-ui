// Package objectstore is an S3-compatible client, small enough to be read.
//
// It exists because this application takes no new module dependency, and
// because the part of the S3 API it needs is three verbs. Signature Version 4
// is HMAC-SHA256 applied four times to strings this file builds explicitly, so
// the whole of it is the standard library.
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

// Credentials are the access key pair. They are never logged and never appear
// in a URL: this client signs with headers only.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

// ErrUnsignedPayloadRefused rejects a request this client will not sign.
//
// S3 allows UNSIGNED-PAYLOAD, and this client does not offer it. Everything it
// sends is a snapshot of somebody's ~/.ssh; signing the body is what makes a
// modified body a rejected request rather than an accepted one.
var ErrUnsignedPayloadRefused = errors.New("this client always signs the payload")

const (
	algorithm            = "AWS4-HMAC-SHA256"
	contentSHA256Header  = "X-Amz-Content-Sha256"
	dateHeader           = "X-Amz-Date"
	unsignedPayloadValue = "UNSIGNED-PAYLOAD"
	timeFormat           = "20060102T150405Z"
	dateFormat           = "20060102"
)

// Sign adds Authorization, X-Amz-Date and X-Amz-Content-Sha256 to request.
//
// payload is the exact body; a nil payload signs the hash of the empty string,
// which is what a GET or a HEAD has. now is a parameter rather than a call to
// time.Now so that every test is exact rather than approximately right.
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

// CanonicalRequest builds the canonical request string. It is exported because
// the published AWS test vectors give it explicitly, and a signer tested only
// on its final signature tells you nothing about where it went wrong.
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

// StringToSign builds the string the signature is computed over.
func StringToSign(algorithmName string, stamp time.Time, scope, canonical string) string {
	return strings.Join([]string{
		algorithmName,
		stamp.UTC().Format(timeFormat),
		scope,
		hashHex([]byte(canonical)),
	}, "\n")
}

// canonicalHeaderSet returns the signed header list and the canonical header
// block. Every header on the request is signed: this client sets only the ones
// it means to send, so signing all of them is both simpler and stricter than
// choosing a subset.
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

// escape is RFC 3986 unreserved-only percent encoding. net/url's QueryEscape
// turns a space into "+", which SigV4 does not accept.
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
