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
	// ErrPreconditionFailed reports that the object changed since it was last
	// read. It is the compare-and-swap failing, which is the whole point of
	// this client: it is how "auto" sync cannot clobber another machine.
	ErrPreconditionFailed = errors.New("the object changed since it was last read")
	// ErrNotFound reports that no object exists under that key.
	ErrNotFound = errors.New("no object under that key")
	// ErrRefused reports any other rejection. The body is not carried: an S3
	// error document names the bucket and the request id, and neither belongs
	// in a message this application shows.
	ErrRefused = errors.New("the object store refused the request")
	// ErrBothConditions rejects a call that sets If-Match and If-None-Match at
	// once. It is a programming error, caught before a request is sent.
	ErrBothConditions = errors.New("If-Match and If-None-Match are mutually exclusive")
	// ErrObjectTooLarge refuses a body above the single-request limit.
	ErrObjectTooLarge = errors.New("the object is too large for a single request")
)

// MaxObjectBytes is the largest snapshot this client will send or accept.
//
// S3 allows 5 GiB in one PUT and this is far below that, because a ~/.ssh is
// kilobytes and anything approaching this ceiling means something has gone
// wrong rather than that someone has a large configuration.
const MaxObjectBytes = 256 << 20

// Object is a fetched object and its entity tag.
type Object struct {
	Body []byte
	// ETag identifies this exact version. It is what a later conditional write
	// is compared against, and it is the only thing this client remembers
	// about the remote.
	ETag string
}

// Client speaks the part of the S3 API this application needs.
type Client struct {
	HTTP *http.Client
	// Endpoint is the account endpoint, for example
	// https://<account>.r2.cloudflarestorage.com. It must be https.
	Endpoint string
	Bucket   string
	// Region is "auto" for R2.
	Region string
	Creds  Credentials
	Now    func() time.Time
}

// ErrInsecureEndpoint refuses a plaintext endpoint. The body is encrypted
// before it gets here, but the credentials are not, and a signature replayed
// off the wire is a live request until its clock skew window closes.
var ErrInsecureEndpoint = errors.New("the object store endpoint must be https")

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
		return "", ErrInsecureEndpoint
	}
	parsed.Path = "/" + strings.Trim(c.Bucket, "/") + "/" + strings.TrimPrefix(key, "/")
	return parsed.String(), nil
}

// Get fetches the object and its ETag.
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

// Head returns the ETag without the body.
func (c Client) Head(ctx context.Context, key string) (string, error) {
	response, err := c.do(ctx, http.MethodHead, key, nil, "", "")
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	return response.Header.Get("ETag"), nil
}

// Put writes the object and returns the new ETag.
//
// ifMatch and ifNoneMatch are the compare-and-swap. Exactly one of them is
// used by this application's callers: If-None-Match: * for the first write,
// and If-Match: <the ETag we last saw> for every write after it. An
// unconditional write is possible but no caller here makes one, because a
// write that cannot fail is a write that can overwrite another machine.
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
		// 412 is the documented answer to a failed If-Match or If-None-Match.
		// 409 is here because a store that serialises conflicting writes may
		// answer with it instead, and both mean the same thing to a caller:
		// somebody else got there first.
		return nil, ErrPreconditionFailed
	default:
		return nil, ErrRefused
	}
}
