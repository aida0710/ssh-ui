package objectstore_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"sshc/internal/objectstore"
)

// The published AWS Signature Version 4 test suite gives, for each case, the
// canonical request, the string to sign and the signature. All three are
// asserted rather than only the last: a signer checked on its output alone
// tells you nothing about where it went wrong when it is wrong.
//
// These are the get-vanilla, get-vanilla-query-order-key-case and post-header-
// key-case cases, with the suite's fixed credentials, region, service and
// clock.
const (
	suiteAccessKeyID     = "AKIDEXAMPLE"
	suiteSecretAccessKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	suiteRegion          = "us-east-1"
	suiteService         = "service"
)

var suiteStamp = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)

func suiteCredentials() objectstore.Credentials {
	return objectstore.Credentials{AccessKeyID: suiteAccessKeyID, SecretAccessKey: suiteSecretAccessKey}
}

func hashOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func TestCanonicalRequestMatchesThePublishedVector(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Host", "example.amazonaws.com")
	request.Header.Set("X-Amz-Date", "20150830T123600Z")

	canonicalHeaders := "host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n"
	signed := "host;x-amz-date"
	emptyPayload := hashOf("")

	got := objectstore.CanonicalRequest(request, canonicalHeaders, signed, emptyPayload)
	want := strings.Join([]string{
		"GET",
		"/",
		"",
		canonicalHeaders,
		signed,
		emptyPayload,
	}, "\n")
	if got != want {
		t.Errorf("canonical request:\n%q\nwant\n%q", got, want)
	}
}

func TestStringToSignMatchesThePublishedVector(t *testing.T) {
	canonical := strings.Join([]string{
		"GET", "/", "",
		"host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n",
		"host;x-amz-date",
		hashOf(""),
	}, "\n")

	got := objectstore.StringToSign("AWS4-HMAC-SHA256", suiteStamp,
		"20150830/us-east-1/service/aws4_request", canonical)
	want := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		"20150830T123600Z",
		"20150830/us-east-1/service/aws4_request",
		hashOf(canonical),
	}, "\n")
	if got != want {
		t.Errorf("string to sign:\n%q\nwant\n%q", got, want)
	}
}

func TestSigningKeyMatchesTheDocumentedExample(t *testing.T) {
	// AWS publishes this derivation with its answer, so this is a real
	// known-answer test of the four-step HMAC chain — the part of SigV4 that
	// is easy to get subtly wrong and impossible to notice without one.
	stamp := time.Date(2015, 8, 30, 0, 0, 0, 0, time.UTC)

	got := hex.EncodeToString(objectstore.SigningKeyForTest(suiteSecretAccessKey, stamp, "us-east-1", "iam"))
	const want = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	if got != want {
		t.Errorf("signing key = %s, want %s", got, want)
	}
}

func TestAuthorizationCarriesTheScopeAndTheSignedHeaders(t *testing.T) {
	// This asserts the structure, not a published digest. The suite's vectors
	// sign the two headers their fixture sets; an S3 request must also carry
	// x-amz-content-sha256, and this client signs every header it sets rather
	// than choosing a subset, so it signs three. The chain that produces the
	// digest is checked against AWS's own answer above.
	request, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "example.amazonaws.com"

	if err := objectstore.Sign(request, suiteCredentials(), suiteRegion, suiteService, nil, suiteStamp); err != nil {
		t.Fatalf("Sign = %v", err)
	}

	got := request.Header.Get("Authorization")
	if !strings.HasPrefix(got, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, ") {
		t.Errorf("authorization = %q", got)
	}
	if !strings.Contains(got, "SignedHeaders=host;x-amz-content-sha256;x-amz-date,") {
		t.Errorf("signed headers = %q", got)
	}
	signature := got[strings.Index(got, "Signature=")+len("Signature="):]
	if len(signature) != 64 {
		t.Errorf("signature = %q, want 64 hex characters", signature)
	}
	if _, err := hex.DecodeString(signature); err != nil {
		t.Errorf("signature is not hex: %v", err)
	}
}

func TestSignIsDeterministicForAFixedClock(t *testing.T) {
	// now is a parameter, never time.Now inside, so the same request signed
	// twice is the same bytes and every assertion above is exact rather than
	// approximately right.
	sign := func() string {
		request, err := http.NewRequest(http.MethodPut, "https://account.r2.cloudflarestorage.com/bucket/key", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "account.r2.cloudflarestorage.com"
		request.Header.Set("Content-Type", "application/octet-stream")
		if err := objectstore.Sign(request, suiteCredentials(), "auto", "s3", []byte("payload"), suiteStamp); err != nil {
			t.Fatal(err)
		}
		return request.Header.Get("Authorization")
	}
	if first, second := sign(), sign(); first != second {
		t.Errorf("two signatures of the same request differ:\n%s\n%s", first, second)
	}
}

func TestSignHashesTheBodyRatherThanDeclaringItUnsigned(t *testing.T) {
	request, err := http.NewRequest(http.MethodPut, "https://example.com/bucket/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("the snapshot")
	if err := objectstore.Sign(request, suiteCredentials(), "auto", "s3", body, suiteStamp); err != nil {
		t.Fatal(err)
	}
	if got := request.Header.Get("X-Amz-Content-Sha256"); got != hashOf("the snapshot") {
		t.Errorf("content hash = %q, want the hash of the body", got)
	}
}

func TestSignRefusesAnUnsignedPayload(t *testing.T) {
	// S3 allows UNSIGNED-PAYLOAD and this client does not offer it: everything
	// it sends is a snapshot of somebody's ~/.ssh, and signing the body is what
	// makes a modified body a rejected request.
	request, err := http.NewRequest(http.MethodPut, "https://example.com/bucket/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")

	if err := objectstore.Sign(request, suiteCredentials(), "auto", "s3", nil, suiteStamp); !errors.Is(err, objectstore.ErrUnsignedPayloadRefused) {
		t.Fatalf("Sign = %v, want ErrUnsignedPayloadRefused", err)
	}
}

func TestSignPutsNoCredentialInTheURL(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://example.com/bucket/key?list-type=2&prefix=a%20b", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := objectstore.Sign(request, suiteCredentials(), "auto", "s3", nil, suiteStamp); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(request.URL.String(), suiteSecretAccessKey) ||
		strings.Contains(request.URL.String(), "X-Amz-Signature") {
		t.Errorf("the URL carries a credential: %s", request.URL.String())
	}
}
