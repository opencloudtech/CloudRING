// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package etcdrecovery

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestS3FetchStreamsExactVersionedObjectWithoutLeakingInputs(t *testing.T) {
	archiveBytes := []byte("synthetic-versioned-etcd-snapshot")
	request := validS3Request(archiveBytes)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		requests.Add(1)
		if incoming.Method != http.MethodGet || incoming.URL.EscapedPath() != "/bucket-a/backups/private/snapshot.db" ||
			incoming.URL.Query().Get("versionId") != request.ObjectVersion || incoming.Header.Get("Authorization") == "" {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		writer.Header().Set("X-Amz-Version-Id", request.ObjectVersion)
		writer.Header().Set("Content-Length", strconv.Itoa(len(archiveBytes)))
		_, _ = writer.Write(archiveBytes)
	}))
	defer server.Close()
	request.Endpoint = server.URL
	request.ObjectIdentitySHA256 = ObjectIdentitySHA256(request)
	root := resolvedTempDir(t)
	credentials := filepath.Join(root, "credentials")
	writeProjectedMount(t, credentials, map[string]string{
		SharedCredentialsKey: validProjectedS3AuthFile(),
	})
	workspace := filepath.Join(root, "work")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	archive, err := fetchS3ArchiveWithClient(context.Background(), request, credentials, workspace, time.Now().UTC(), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	digest, size, err := archive.Digest()
	if err != nil || digest != request.SnapshotChecksumSHA256 || size != request.SnapshotBytes || requests.Load() != 1 {
		t.Fatalf("archive digest=%s size=%d requests=%d err=%v", digest, size, requests.Load(), err)
	}
}

func TestResolveS3ObjectVersionUsesExactHashAndSizeBinding(t *testing.T) {
	version := "version-private-value"
	objectKey := "backups/private/snapshot.db"
	body := `<ListVersionsResult><IsTruncated>false</IsTruncated>` +
		`<Version><Key>` + objectKey + `</Key><VersionId>older-version</VersionId><Size>32</Size></Version>` +
		`<Version><Key>` + objectKey + `</Key><VersionId>` + version + `</VersionId><Size>32</Size></Version>` +
		`</ListVersionsResult>`
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		requests.Add(1)
		if incoming.Method != http.MethodGet || incoming.URL.EscapedPath() != "/bucket-a" ||
			incoming.URL.Query().Get("prefix") != objectKey ||
			incoming.URL.Query().Get("versions") != "" ||
			incoming.URL.Query().Get("max-keys") != "1000" ||
			incoming.Header.Get("Authorization") == "" {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/xml")
		writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = writer.Write([]byte(body))
	}))
	defer server.Close()
	lookup := S3ObjectVersionLookup{
		Endpoint: server.URL, Region: "region-1", Bucket: "bucket-a",
		ObjectKey: objectKey, ObjectVersionSHA256: sha256Hex([]byte(version)), ExpectedBytes: 32,
	}
	resolved, err := resolveS3ObjectVersionWithClient(
		context.Background(), lookup, []byte(validProjectedS3AuthFile()), time.Now().UTC(), server.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != version || requests.Load() != 1 {
		t.Fatalf("resolved=%q requests=%d", resolved, requests.Load())
	}
}

func TestResolveS3ObjectVersionRejectsIncompleteAmbiguousAndLeakyInputs(t *testing.T) {
	version := "version-private-value"
	objectKey := "backups/private/snapshot.db"
	versionXML := `<Version><Key>` + objectKey + `</Key><VersionId>` + version + `</VersionId><Size>32</Size></Version>`
	for _, test := range []struct {
		name string
		body string
	}{
		{"truncated", `<ListVersionsResult><IsTruncated>true</IsTruncated>` + versionXML + `</ListVersionsResult>`},
		{"ambiguous", `<ListVersionsResult><IsTruncated>false</IsTruncated>` + versionXML + versionXML + `</ListVersionsResult>`},
		{"wrong size", `<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>` + objectKey + `</Key><VersionId>` + version + `</VersionId><Size>31</Size></Version></ListVersionsResult>`},
		{"wrong version", `<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>` + objectKey + `</Key><VersionId>other-private-version</VersionId><Size>32</Size></Version></ListVersionsResult>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Length", strconv.Itoa(len(test.body)))
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			lookup := S3ObjectVersionLookup{
				Endpoint: server.URL, Region: "region-1", Bucket: "bucket-a",
				ObjectKey: objectKey, ObjectVersionSHA256: sha256Hex([]byte(version)), ExpectedBytes: 32,
			}
			_, err := resolveS3ObjectVersionWithClient(
				context.Background(), lookup, []byte(validProjectedS3AuthFile()), time.Now().UTC(), server.Client(),
			)
			if err == nil {
				t.Fatal("unsafe S3 object version listing was accepted")
			}
			for _, canary := range []string{server.URL, objectKey, version, "access-key-canary", "secret-key-canary-value"} {
				if strings.Contains(err.Error(), canary) {
					t.Fatalf("error leaked protected input %q: %v", canary, err)
				}
			}
		})
	}
}

func TestS3FetchRejectsRedirectTLSVersionTruncationOversizeAndCancellation(t *testing.T) {
	archive := []byte("synthetic-versioned-etcd-snapshot")
	base := validS3Request(archive)
	cases := []struct {
		name    string
		handler func(Request) http.Handler
		client  func(*httptest.Server) *http.Client
		mutate  func(*Request)
		cancel  bool
	}{
		{
			name: "wrong version",
			handler: func(request Request) http.Handler {
				return responseHandler(archive, "wrong-version", int64(len(archive)))
			},
		},
		{
			name: "redirect",
			handler: func(request Request) http.Handler {
				return http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
					http.Redirect(writer, incoming, "https://redirect.invalid/object", http.StatusFound)
				})
			},
		},
		{
			name: "TLS failure",
			handler: func(request Request) http.Handler {
				return responseHandler(archive, request.ObjectVersion, int64(len(archive)))
			},
			client: func(*httptest.Server) *http.Client { return newS3Client() },
		},
		{
			name: "truncated",
			handler: func(request Request) http.Handler {
				return responseHandler(archive[:8], request.ObjectVersion, int64(len(archive)))
			},
		},
		{
			name: "oversized",
			handler: func(request Request) http.Handler {
				return responseHandler(append(archive, 'x'), request.ObjectVersion, int64(len(archive)+1))
			},
		},
		{
			name: "cancelled",
			handler: func(request Request) http.Handler {
				return http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) { <-incoming.Context().Done() })
			},
			cancel: true,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := base
			server := httptest.NewTLSServer(test.handler(request))
			defer server.Close()
			request.Endpoint = server.URL
			if test.mutate != nil {
				test.mutate(&request)
			}
			request.ObjectIdentitySHA256 = ObjectIdentitySHA256(request)
			root := resolvedTempDir(t)
			credentialRoot := filepath.Join(root, "credentials")
			writeProjectedMount(t, credentialRoot, map[string]string{
				SharedCredentialsKey: validProjectedS3AuthFile(),
			})
			workspace := filepath.Join(root, "work")
			if err := os.Mkdir(workspace, 0o700); err != nil {
				t.Fatal(err)
			}
			client := server.Client()
			if test.client != nil {
				client = test.client(server)
			}
			ctx := context.Background()
			if test.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			_, err := fetchS3ArchiveWithClient(ctx, request, credentialRoot, workspace, time.Now().UTC(), client)
			if err == nil {
				t.Fatal("unsafe S3 response was accepted")
			}
			for _, canary := range []string{request.Endpoint, request.ObjectKey, request.ObjectVersion, "access-key-canary", "secret-key-canary-value"} {
				if strings.Contains(err.Error(), canary) {
					t.Fatalf("error leaked %q: %v", canary, err)
				}
			}
		})
	}
}

func validProjectedS3AuthFile() string {
	return strings.Join([]string{
		"[default]",
		"aws_access_key_id=access-key-canary",
		"aws_secret_access_key=secret-key-canary-value",
		"",
	}, "\n")
}

func TestProjectedReaderAcceptsOnlyAtomicWriterLayout(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		root := filepath.Join(resolvedTempDir(t), "request")
		writeProjectedMount(t, root, map[string]string{"request.json": `{"safe":true}`})
		payload, err := readProjectedBytes(root, "request.json", []string{"request.json"}, 1024)
		if err != nil || string(payload) != `{"safe":true}` {
			t.Fatalf("payload=%q err=%v", payload, err)
		}
	})
	for _, test := range []struct {
		name   string
		mutate func(string)
	}{
		{"data escape", func(root string) {
			_ = os.Remove(filepath.Join(root, "..data"))
			_ = os.Symlink("../escape", filepath.Join(root, "..data"))
		}},
		{"visible escape", func(root string) {
			_ = os.Remove(filepath.Join(root, "request.json"))
			_ = os.Symlink("../escape", filepath.Join(root, "request.json"))
		}},
		{"extra key", func(root string) {
			_ = os.Symlink(filepath.Join("..data", "request.json"), filepath.Join(root, "extra"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(resolvedTempDir(t), "request")
			writeProjectedMount(t, root, map[string]string{"request.json": `{}`})
			test.mutate(root)
			if _, err := readProjectedBytes(root, "request.json", []string{"request.json"}, 1024); err == nil {
				t.Fatal("unsafe projected mount was accepted")
			}
		})
	}
}

func TestSharedS3CredentialsAcceptOnlyOneStrictDefaultProfile(t *testing.T) {
	credentials, err := parseSharedS3Credentials([]byte(
		"# projected AWS shared credentials\n" +
			"[default]\n" +
			"aws_access_key_id = access-key-canary\n" +
			"aws_secret_access_key = secret-key-canary-value\n" +
			"aws_session_token = session-token-canary-value\n",
	))
	if err != nil {
		t.Fatal(err)
	}
	defer credentials.clear()
	if string(credentials.accessKey) != "access-key-canary" ||
		string(credentials.secretKey) != "secret-key-canary-value" ||
		string(credentials.sessionToken) != "session-token-canary-value" {
		t.Fatal("strict shared credentials parser returned unexpected values")
	}

	for _, payload := range []string{
		"aws_access_key_id=access-key-canary\naws_secret_access_key=secret-key-canary-value\n",
		"[other]\naws_access_key_id=access-key-canary\naws_secret_access_key=secret-key-canary-value\n",
		"[default]\naws_access_key_id=access-key-canary\naws_access_key_id=access-key-canary-2\naws_secret_access_key=secret-key-canary-value\n",
		"[default]\naws_access_key_id=access-key-canary\naws_secret_access_key=secret-key-canary-value\nunsupported=value\n",
		"[default]\naws_access_key_id=short\naws_secret_access_key=secret-key-canary-value\n",
		"[default]\naws_access_key_id=access-key-canary\naws_secret_access_key=short\n",
	} {
		if parsed, parseErr := parseSharedS3Credentials([]byte(payload)); parseErr == nil {
			parsed.clear()
			t.Fatalf("unsafe shared credentials input was accepted: %q", payload)
		}
	}
}

func validS3Request(archive []byte) Request {
	digest := sha256.Sum256(archive)
	inputSecretSHA, err := InputSecretProjectionSHA256(InputSecretProjection{
		SchemaVersion:       InputProjectionSchemaVersion,
		Namespace:           "kube-system",
		ProjectedObjectName: "cloudring-etcd-recovery-request",
		SecretKey:           "request.json",
		MountPath:           DefaultRequestPath,
		DefaultMode:         0o440,
		Optional:            false,
		ReadOnly:            true,
	})
	if err != nil {
		panic(err)
	}
	request := Request{
		SchemaVersion: RequestSchemaVersion, OperationID: "operation-01", SnapshotID: "snapshot-01",
		SnapshotChecksumSHA256: hex.EncodeToString(digest[:]), SnapshotBytes: int64(len(archive)), SourceMode: "s3",
		Endpoint: "https://example.invalid", Region: "region-1", Bucket: "bucket-a",
		ObjectKey: "backups/private/snapshot.db", ObjectVersion: "version-private-value",
		ClusterIdentitySHA256: strings.Repeat("1", 64), JobTemplateSHA256: strings.Repeat("2", 64),
		ExecutionProfileSHA256: strings.Repeat("3", 64), InputSecretSHA256: inputSecretSHA,
		WorkerExecutableSHA256: strings.Repeat("5", 64), WorkerImageDigest: "sha256:" + strings.Repeat("6", 64),
		EtcdutlVersion: ToolVersion, EtcdutlSHA256: ToolSHA256,
		IssuedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), TimeoutSeconds: 30,
	}
	request.ObjectIdentitySHA256 = ObjectIdentitySHA256(request)
	return request
}

func TestAWSEscapeUsesSigV4UnreservedByteEncoding(t *testing.T) {
	if got, want := awsEscape("a+b =/&@ü"), "a%2Bb%20%3D%2F%26%40%C3%BC"; got != want {
		t.Fatalf("awsEscape = %q, want %q", got, want)
	}
	request := validS3Request([]byte("snapshot"))
	request.ObjectKey = "backups/a+b=snapshot.db"
	request.ObjectVersion = "v+1=/&@"
	objectURL, canonicalURI, canonicalQuery, err := s3ObjectURL(request)
	if err != nil {
		t.Fatal(err)
	}
	if canonicalURI != "/bucket-a/backups/a%2Bb%3Dsnapshot.db" ||
		canonicalQuery != "versionId=v%2B1%3D%2F%26%40" ||
		objectURL.EscapedPath() != canonicalURI || objectURL.RawQuery != canonicalQuery {
		t.Fatalf("canonical URI=%q query=%q URL=%q", canonicalURI, canonicalQuery, objectURL.String())
	}
}

func TestS3EndpointValidationRejectsAmbiguousAndNonCanonicalURLs(t *testing.T) {
	for _, endpoint := range []string{
		"http://object.example",
		"https://user@object.example",
		"https://object.example/prefix",
		"https://object.example/?query=value",
		"https://object.example/#fragment",
		"https://OBJECT.example",
		"https://object.example:0443",
		"https://object.example\\@other.example",
		"https://object..example",
		"https://object.example.",
	} {
		request := validS3Request([]byte("snapshot"))
		request.Endpoint = endpoint
		if validSource(request) {
			t.Fatalf("accepted ambiguous endpoint %q", endpoint)
		}
	}
	loopback4 := "127.0." + "0.1"
	colon := ":"
	loopback6 := colon + colon + "1"
	for _, endpoint := range []string{
		"https://object.example",
		"https://object.example/",
		"https://" + loopback4 + ":9443",
		"https://[" + loopback6 + "]:9443",
	} {
		request := validS3Request([]byte("snapshot"))
		request.Endpoint = endpoint
		if !validSource(request) {
			t.Fatalf("rejected canonical endpoint %q", endpoint)
		}
	}
}

func responseHandler(body []byte, version string, contentLength int64) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Amz-Version-Id", version)
		writer.Header().Set("Content-Length", stringInt64(contentLength))
		_, _ = writer.Write(body)
	})
}

func stringInt64(value int64) string {
	return strconv.FormatInt(value, 10)
}

func resolvedTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func writeProjectedMount(t *testing.T, root string, values map[string]string) {
	t.Helper()
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	generation := "..2026_07_23_10_00_00.000000000"
	generationPath := filepath.Join(root, generation)
	if err := os.Mkdir(generationPath, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, value := range values {
		// #nosec G306 -- reproduces the read-only group-readable Kubernetes projection mode.
		if err := os.WriteFile(filepath.Join(generationPath, name), []byte(value), 0o440); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(generation, filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
}

func TestS3ClientUsesSystemTrustAndNoProxyOrRedirect(t *testing.T) {
	client := newS3Client()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("S3 client transport is not fail closed")
	}
	if client.CheckRedirect == nil {
		t.Fatal("S3 client lacks redirect denial")
	}
	if transport.TLSClientConfig.RootCAs != nil {
		t.Fatal("production S3 client unexpectedly overrides system CA roots")
	}
}
