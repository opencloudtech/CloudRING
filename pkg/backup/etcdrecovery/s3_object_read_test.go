// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package etcdrecovery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadS3ObjectBindsHeadMetadataAndVersionedGet(t *testing.T) {
	body := []byte("selected base backup bytes")
	version := "version-private-value"
	etag := `"etag-private-value"`
	lastModified := time.Date(2026, time.July, 23, 10, 0, 0, 123456789, time.UTC)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		requests.Add(1)
		if incoming.URL.EscapedPath() != "/bucket-a/backups/private/snapshot.db" ||
			incoming.Header.Get("If-Match") != etag || incoming.Header.Get("Authorization") == "" {
			http.Error(writer, "invalid request", http.StatusBadRequest)
			return
		}
		writer.Header().Set("ETag", etag)
		writer.Header().Set("X-Amz-Version-Id", version)
		writer.Header().Set("Last-Modified", lastModified.UTC().Format(http.TimeFormat))
		writer.Header().Set("Content-Length", stringInt64(int64(len(body))))
		switch incoming.Method {
		case http.MethodHead:
			if incoming.URL.RawQuery != "" {
				http.Error(writer, "HEAD must not carry a version", http.StatusBadRequest)
				return
			}
			writer.WriteHeader(http.StatusOK)
		case http.MethodGet:
			if incoming.URL.Query().Get("versionId") != version {
				http.Error(writer, "GET must carry the selected version", http.StatusBadRequest)
				return
			}
			_, _ = writer.Write(body)
		default:
			http.Error(writer, "unexpected method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	credentials := []byte(validProjectedS3AuthFile())
	request := S3ObjectReadRequest{
		Endpoint: server.URL, Region: "region-1", Bucket: "bucket-a",
		ObjectKey: "backups/private/snapshot.db", ExpectedBytes: int64(len(body)), ExpectedETag: etag,
		ExpectedLastModified: lastModified,
	}
	result, err := readS3ObjectWithClient(context.Background(), request, credentials, time.Now().UTC(), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(body)
	if result.Bytes != int64(len(body)) || result.ContentSHA256 != hex.EncodeToString(wantDigest[:]) ||
		result.ObjectVersionSHA256 != sha256Hex([]byte(version)) || requests.Load() != 2 {
		t.Fatalf("result=%+v requests=%d", result, requests.Load())
	}
	if !bytes.Equal(credentials, []byte(validProjectedS3AuthFile())) {
		t.Fatal("read mutated caller-owned credentials")
	}
}

func TestS3SignerBindsHTTPMethodForHeadAndGet(t *testing.T) {
	credentials, err := parseSharedS3Credentials([]byte(validProjectedS3AuthFile()))
	if err != nil {
		t.Fatal(err)
	}
	defer credentials.clear()
	now := time.Date(2026, time.July, 23, 10, 0, 0, 0, time.UTC)
	region := "region-1"
	canonicalURI := "/bucket-a/backups/private/snapshot.db"
	canonicalQuery := "versionId=version-private-value"
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		request, err := http.NewRequest(method, "https://objects.example.invalid/bucket-a/backups/private/snapshot.db", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
		if err := signS3Request(request, region, canonicalURI, canonicalQuery, now, credentials); err != nil {
			t.Fatal(err)
		}
		want := independentS3Authorization(method, request.URL.Host, canonicalURI, canonicalQuery, region, now, credentials)
		if got := request.Header.Get("Authorization"); got != want {
			t.Fatalf("%s signature mismatch", method)
		}
	}

	headRequest, _ := http.NewRequest(http.MethodHead, "https://objects.example.invalid/bucket-a/backups/private/snapshot.db", nil)
	getRequest, _ := http.NewRequest(http.MethodGet, "https://objects.example.invalid/bucket-a/backups/private/snapshot.db", nil)
	headRequest.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	getRequest.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	if err := signS3Request(headRequest, region, canonicalURI, canonicalQuery, now, credentials); err != nil {
		t.Fatal(err)
	}
	if err := signS3Request(getRequest, region, canonicalURI, canonicalQuery, now, credentials); err != nil {
		t.Fatal(err)
	}
	if headRequest.Header.Get("Authorization") == getRequest.Header.Get("Authorization") {
		t.Fatal("HEAD and GET signatures are identical")
	}
}

func TestReadS3ObjectRejectsChangedIdentityRedirectTLSAndBounds(t *testing.T) {
	body := []byte("selected base backup bytes")
	version := "version-private-value"
	etag := `"etag-private-value"`
	lastModified := time.Date(2026, time.July, 23, 10, 0, 0, 0, time.UTC)
	base := S3ObjectReadRequest{
		Region: "region-1", Bucket: "bucket-a", ObjectKey: "backups/private/snapshot.db",
		ExpectedBytes: int64(len(body)), ExpectedETag: etag, ExpectedLastModified: lastModified,
	}
	tests := []struct {
		name    string
		handler func(S3ObjectReadRequest) http.Handler
		client  func(*httptest.Server) *http.Client
	}{
		{
			name: "changed version",
			handler: func(request S3ObjectReadRequest) http.Handler {
				return s3ReadIdentityHandler(request, body, version, etag, version+"-changed", etag, int64(len(body)))
			},
		},
		{
			name: "changed etag",
			handler: func(request S3ObjectReadRequest) http.Handler {
				return s3ReadIdentityHandler(request, body, version, etag, version, `"etag-changed"`, int64(len(body)))
			},
		},
		{
			name: "changed size",
			handler: func(request S3ObjectReadRequest) http.Handler {
				return s3ReadIdentityHandler(request, body, version, etag, version, etag, int64(len(body)+1))
			},
		},
		{
			name: "redirect",
			handler: func(request S3ObjectReadRequest) http.Handler {
				return http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
					http.Redirect(writer, incoming, "https://redirect.invalid/object", http.StatusFound)
				})
			},
		},
		{
			name: "TLS failure",
			handler: func(request S3ObjectReadRequest) http.Handler {
				return s3ReadIdentityHandler(request, body, version, etag, version, etag, int64(len(body)))
			},
			client: func(*httptest.Server) *http.Client { return newS3Client() },
		},
		{
			name: "oversized",
			handler: func(request S3ObjectReadRequest) http.Handler {
				return s3ReadIdentityHandler(request, append(body, 'x'), version, etag, version, etag, int64(len(body)+1))
			},
		},
		{
			name: "truncated",
			handler: func(request S3ObjectReadRequest) http.Handler {
				return s3ReadIdentityHandler(request, body[:len(body)-1], version, etag, version, etag, int64(len(body)))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(test.handler(base))
			defer server.Close()
			request := base
			request.Endpoint = server.URL
			client := server.Client()
			if test.client != nil {
				client = test.client(server)
			}
			_, err := readS3ObjectWithClient(context.Background(), request, []byte(validProjectedS3AuthFile()), time.Now().UTC(), client)
			if err == nil {
				t.Fatal("unsafe S3 object response was accepted")
			}
			for _, canary := range []string{request.Endpoint, request.ObjectKey, version, etag, "access-key-canary", "secret-key-canary-value"} {
				if strings.Contains(err.Error(), canary) {
					t.Fatalf("error leaked protected input %q: %v", canary, err)
				}
			}
		})
	}
}

func TestReadS3ObjectCancellationAndInvalidInputs(t *testing.T) {
	body := []byte("selected base backup bytes")
	version := "version-private-value"
	etag := `"etag-private-value"`
	lastModified := time.Date(2026, time.July, 23, 10, 0, 0, 0, time.UTC)
	base := S3ObjectReadRequest{
		Region: "region-1", Bucket: "bucket-a", ObjectKey: "backups/private/snapshot.db",
		ExpectedBytes: int64(len(body)), ExpectedETag: etag, ExpectedLastModified: lastModified,
	}
	getStarted := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		writer.Header().Set("ETag", etag)
		writer.Header().Set("X-Amz-Version-Id", version)
		writer.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
		writer.Header().Set("Content-Length", stringInt64(int64(len(body))))
		if incoming.Method == http.MethodHead {
			writer.WriteHeader(http.StatusOK)
			return
		}
		close(getStarted)
		<-incoming.Context().Done()
	}))
	defer server.Close()
	request := base
	request.Endpoint = server.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan error, 1)
	go func() {
		_, err := readS3ObjectWithClient(ctx, request, []byte(validProjectedS3AuthFile()), time.Now().UTC(), server.Client())
		resultCh <- err
	}()
	select {
	case <-getStarted:
		cancel()
	case <-time.After(3 * time.Second):
		t.Fatal("GET was not started")
	}
	select {
	case err := <-resultCh:
		if err == nil {
			t.Fatal("cancelled S3 object read succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled S3 object read did not return")
	}

	invalid := []struct {
		name    string
		ctx     context.Context
		request S3ObjectReadRequest
		now     time.Time
		secret  []byte
	}{
		{name: "nil context", request: base, now: time.Now().UTC(), secret: []byte(validProjectedS3AuthFile())},
		{name: "zero time", ctx: context.Background(), request: base, secret: []byte(validProjectedS3AuthFile())},
		{name: "endpoint", ctx: context.Background(), request: func() S3ObjectReadRequest { value := base; value.Endpoint = "http://not-https"; return value }(), now: time.Now().UTC(), secret: []byte(validProjectedS3AuthFile())},
		{name: "region", ctx: context.Background(), request: func() S3ObjectReadRequest { value := base; value.Region = "Region-1"; return value }(), now: time.Now().UTC(), secret: []byte(validProjectedS3AuthFile())},
		{name: "bucket", ctx: context.Background(), request: func() S3ObjectReadRequest { value := base; value.Bucket = "bad_bucket"; return value }(), now: time.Now().UTC(), secret: []byte(validProjectedS3AuthFile())},
		{name: "key", ctx: context.Background(), request: func() S3ObjectReadRequest { value := base; value.ObjectKey = "../private"; return value }(), now: time.Now().UTC(), secret: []byte(validProjectedS3AuthFile())},
		{name: "zero bytes", ctx: context.Background(), request: func() S3ObjectReadRequest { value := base; value.ExpectedBytes = 0; return value }(), now: time.Now().UTC(), secret: []byte(validProjectedS3AuthFile())},
		{name: "too many bytes", ctx: context.Background(), request: func() S3ObjectReadRequest { value := base; value.ExpectedBytes = MaxArchiveBytes + 1; return value }(), now: time.Now().UTC(), secret: []byte(validProjectedS3AuthFile())},
		{name: "wildcard etag", ctx: context.Background(), request: func() S3ObjectReadRequest { value := base; value.ExpectedETag = "*"; return value }(), now: time.Now().UTC(), secret: []byte(validProjectedS3AuthFile())},
		{name: "invalid credentials", ctx: context.Background(), request: base, now: time.Now().UTC(), secret: []byte("[default]\naws_secret_access_key=private-secret-value\n")},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			_, err := readS3ObjectWithClient(test.ctx, test.request, test.secret, test.now, server.Client())
			if err == nil {
				t.Fatal("invalid S3 object input was accepted")
			}
			for _, canary := range []string{test.request.Endpoint, test.request.ObjectKey, version, etag, "private-secret-value"} {
				if canary != "" && strings.Contains(err.Error(), canary) {
					t.Fatalf("error leaked protected input %q: %v", canary, err)
				}
			}
		})
	}
}

func TestReadS3ObjectRejectsMissingOrChangedLastModified(t *testing.T) {
	body := []byte("selected base backup bytes")
	version := "version-private-value"
	etag := `"etag-private-value"`
	expected := time.Date(2026, time.July, 23, 10, 0, 0, 987654321, time.UTC)
	changed := expected.Add(time.Second)
	base := S3ObjectReadRequest{
		Region: "region-1", Bucket: "bucket-a", ObjectKey: "backups/private/snapshot.db",
		ExpectedBytes: int64(len(body)), ExpectedETag: etag, ExpectedLastModified: expected,
	}
	for _, test := range []struct {
		name     string
		headDate string
		getDate  string
	}{
		{name: "missing HEAD date", headDate: "", getDate: expected.Format(http.TimeFormat)},
		{name: "changed HEAD date", headDate: changed.Format(http.TimeFormat), getDate: expected.Format(http.TimeFormat)},
		{name: "changed GET date", headDate: expected.Format(http.TimeFormat), getDate: changed.Format(http.TimeFormat)},
		{name: "invalid date", headDate: "not-an-http-date", getDate: expected.Format(http.TimeFormat)},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
				writer.Header().Set("ETag", etag)
				writer.Header().Set("X-Amz-Version-Id", version)
				writer.Header().Set("Content-Length", stringInt64(int64(len(body))))
				if incoming.Method == http.MethodHead {
					if test.headDate != "" {
						writer.Header().Set("Last-Modified", test.headDate)
					}
					writer.WriteHeader(http.StatusOK)
					return
				}
				if test.getDate != "" {
					writer.Header().Set("Last-Modified", test.getDate)
				}
				_, _ = writer.Write(body)
			}))
			defer server.Close()
			request := base
			request.Endpoint = server.URL
			_, err := readS3ObjectWithClient(context.Background(), request, []byte(validProjectedS3AuthFile()), time.Now().UTC(), server.Client())
			if err == nil {
				t.Fatal("unsafe Last-Modified metadata was accepted")
			}
		})
	}
}

func TestReadS3ObjectRejectsCancellationAtContentBoundary(t *testing.T) {
	body := []byte("selected base backup bytes")
	version := "version-private-value"
	etag := `"etag-private-value"`
	lastModified := time.Date(2026, time.July, 23, 10, 0, 0, 0, time.UTC)
	request := S3ObjectReadRequest{
		Endpoint: "https://objects.example.invalid", Region: "region-1", Bucket: "bucket-a",
		ObjectKey: "backups/private/snapshot.db", ExpectedBytes: int64(len(body)), ExpectedETag: etag,
		ExpectedLastModified: lastModified,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	roundTripper := &cancelAtEOFTransport{body: body, version: version, etag: etag, lastModified: lastModified, cancel: cancel}
	client := &http.Client{Transport: roundTripper}
	_, err := readS3ObjectWithClient(ctx, request, []byte(validProjectedS3AuthFile()), time.Now().UTC(), client)
	if err == nil {
		t.Fatal("S3 object read succeeded after cancellation at EOF")
	}
	if roundTripper.requests.Load() != 2 {
		t.Fatalf("requests=%d, want signed HEAD and GET", roundTripper.requests.Load())
	}
}

func independentS3Authorization(method, host, canonicalURI, canonicalQuery, region string, now time.Time, credentials *s3Credentials) string {
	amzDate := now.UTC().Format("20060102T150405Z")
	date := now.UTC().Format("20060102")
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := "host:" + host + "\n" +
		"x-amz-content-sha256:" + emptyPayloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n"
	canonicalRequest := strings.Join([]string{method, canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, emptyPayloadHash}, "\n")
	canonicalDigest := sha256.Sum256([]byte(canonicalRequest))
	scope := date + "/" + region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(canonicalDigest[:])
	rootKey := append([]byte("AWS4"), credentials.secretKey...)
	dateKey := independentS3HMAC(rootKey, date)
	regionKey := independentS3HMAC(dateKey, region)
	serviceKey := independentS3HMAC(regionKey, "s3")
	signingKey := independentS3HMAC(serviceKey, "aws4_request")
	signature := hex.EncodeToString(independentS3HMAC(signingKey, stringToSign))
	return "AWS4-HMAC-SHA256 Credential=" + string(credentials.accessKey) + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}

func independentS3HMAC(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

type cancelAtEOFTransport struct {
	body         []byte
	version      string
	etag         string
	lastModified time.Time
	cancel       context.CancelFunc
	requests     atomic.Int32
}

func (transport *cancelAtEOFTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.requests.Add(1)
	headers := make(http.Header)
	headers.Set("ETag", transport.etag)
	headers.Set("X-Amz-Version-Id", transport.version)
	headers.Set("Last-Modified", transport.lastModified.Format(http.TimeFormat))
	headers.Set("Content-Length", stringInt64(int64(len(transport.body))))
	if request.Method == http.MethodHead {
		return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: io.NopCloser(strings.NewReader("")), ContentLength: int64(len(transport.body)), Request: request}, nil
	}
	if request.Method == http.MethodGet {
		return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: &cancelAtEOFBody{data: transport.body, cancel: transport.cancel}, ContentLength: int64(len(transport.body)), Request: request}, nil
	}
	return nil, errors.New("unexpected method")
}

type cancelAtEOFBody struct {
	data   []byte
	offset int
	cancel context.CancelFunc
}

func (body *cancelAtEOFBody) Read(buffer []byte) (int, error) {
	if body.offset == len(body.data) {
		body.cancel()
		return 0, io.EOF
	}
	count := copy(buffer, body.data[body.offset:])
	body.offset += count
	return count, nil
}

func (body *cancelAtEOFBody) Close() error { return nil }

func s3ReadIdentityHandler(
	request S3ObjectReadRequest,
	body []byte,
	headVersion, headETag, getVersion, getETag string,
	getLength int64,
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		writer.Header().Set("ETag", headETag)
		writer.Header().Set("X-Amz-Version-Id", headVersion)
		writer.Header().Set("Last-Modified", request.ExpectedLastModified.Format(http.TimeFormat))
		writer.Header().Set("Content-Length", stringInt64(request.ExpectedBytes))
		if incoming.Method == http.MethodHead {
			writer.WriteHeader(http.StatusOK)
			return
		}
		writer.Header().Set("ETag", getETag)
		writer.Header().Set("X-Amz-Version-Id", getVersion)
		writer.Header().Set("Content-Length", stringInt64(getLength))
		_, _ = writer.Write(body)
	})
}
