// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func testSubstrateBearer() string {
	return strings.Repeat("synthetic", 8)
}

func testAPIClient(t *testing.T, handler http.Handler) (*Client, Profile, []byte) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	profile := testProfile()
	profile.Target.APIServer = server.URL
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	user := map[string]any{}
	user["token"] = testSubstrateBearer()
	config := map[string]any{"apiVersion": "v1", "kind": "Config", "current-context": "selected",
		"clusters": []any{map[string]any{"name": "cluster", "cluster": map[string]any{"server": server.URL, "certificate-authority-data": ca}}},
		"users":    []any{map[string]any{"name": "operator", "user": user}},
		"contexts": []any{map[string]any{"name": "selected", "context": map[string]any{"cluster": "cluster", "user": "operator"}}}}
	payload, err := yaml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(bytes.NewReader(payload), profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, profile, payload
}

func TestSubstrateCredentialsRejectAmbientFallbackAndAmbiguity(t *testing.T) {
	_, profile, payload := testAPIClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	var base map[string]any
	if yaml.Unmarshal(payload, &base) != nil {
		t.Fatal("decode fixture")
	}
	for name, mutate := range map[string]func(map[string]any){
		"exec": func(value map[string]any) {
			value["users"].([]any)[0].(map[string]any)["user"].(map[string]any)["exec"] = map[string]any{"command": "leak"}
		},
		"token file": func(value map[string]any) {
			value["users"].([]any)[0].(map[string]any)["user"].(map[string]any)["tokenFile"] = "/private"
		},
		"proxy": func(value map[string]any) {
			value["clusters"].([]any)[0].(map[string]any)["cluster"].(map[string]any)["proxy-url"] = "https://unexpected.test"
		},
		"insecure": func(value map[string]any) {
			value["clusters"].([]any)[0].(map[string]any)["cluster"].(map[string]any)["insecure-skip-tls-verify"] = true
		},
		"CA file": func(value map[string]any) {
			value["clusters"].([]any)[0].(map[string]any)["cluster"].(map[string]any)["certificate-authority"] = "/private"
		},
		"selected context": func(value map[string]any) { value["current-context"] = "other" },
		"multiple contexts": func(value map[string]any) {
			value["contexts"] = append(value["contexts"].([]any), value["contexts"].([]any)[0])
		},
		"different cluster": func(value map[string]any) {
			value["clusters"].([]any)[0].(map[string]any)["cluster"].(map[string]any)["server"] = "https://other.test"
		},
		"token newline": func(value map[string]any) {
			value["users"].([]any)[0].(map[string]any)["user"].(map[string]any)["token"] = "long-enough-token\nInjected:1"
		},
	} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if yaml.Unmarshal(payload, &value) != nil {
				t.Fatal("fixture")
			}
			mutate(value)
			changed, _ := yaml.Marshal(value)
			if _, err := NewClient(bytes.NewReader(changed), profile); !errors.Is(err, ErrCredentials) {
				t.Fatalf("unsafe credential input accepted: %v", err)
			}
		})
	}
	for name, changed := range map[string][]byte{"duplicate": append([]byte("kind: Config\n"), payload...), "two documents": append(append(bytes.Clone(payload), []byte("\n---\n")...), payload...), "alias": []byte("apiVersion: &v v1\nkind: *v\n")} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewClient(bytes.NewReader(changed), profile); !errors.Is(err, ErrCredentials) {
				t.Fatal("ambiguous input accepted")
			}
		})
	}
}

func TestSubstrateRequestsPinTLSAndDoNotFollowRedirectsOrExposeBodies(t *testing.T) {
	var calls atomic.Int32
	client, profile, payload := testAPIClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Header.Get("Authorization") != "Bearer "+testSubstrateBearer() {
			t.Error("missing selected credential")
		}
		switch request.URL.Path {
		case "/redirect":
			writer.Header().Set("Location", "/must-not-follow")
			writer.WriteHeader(http.StatusTemporaryRedirect)
		case "/forbidden":
			writer.WriteHeader(http.StatusForbidden)
			_, _ = writer.Write([]byte(`{"private":"NEVER-IN-DIAGNOSTIC"}`))
		default:
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"verified":true}`))
		}
	}))
	var result map[string]bool
	if err := client.request(context.Background(), http.MethodGet, "/valid", nil, nil, &result); err != nil || !result["verified"] {
		t.Fatalf("verified TLS request failed: %v", err)
	}
	for _, path := range []string{"/redirect", "/forbidden"} {
		err := client.request(context.Background(), http.MethodGet, path, nil, nil, &result)
		if err == nil || strings.Contains(err.Error(), "NEVER-IN-DIAGNOSTIC") {
			t.Fatal("unsafe response handling")
		}
	}
	if calls.Load() != 3 {
		t.Fatal("redirect followed")
	}
	var changed map[string]any
	if err := yaml.Unmarshal(payload, &changed); err != nil {
		t.Fatal("decode TLS test payload")
	}
	wrongCredentials, err := newCredentials(profile, time.Now())
	if err != nil {
		t.Fatalf("generate unrelated CA: %v", err)
	}
	cluster := changed["clusters"].([]any)[0].(map[string]any)["cluster"].(map[string]any)
	cluster["certificate-authority-data"] = base64.StdEncoding.EncodeToString([]byte(wrongCredentials.CACertificate))
	wrongPayload, err := yaml.Marshal(changed)
	if err != nil {
		t.Fatal("encode wrong CA test payload")
	}
	wrongClient, err := NewClient(bytes.NewReader(wrongPayload), profile)
	if err != nil {
		t.Fatalf("construct wrong CA client: %v", err)
	}
	t.Cleanup(func() { _ = wrongClient.Close() })
	if err := wrongClient.request(context.Background(), http.MethodGet, "/valid", nil, nil, &result); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	if calls.Load() != 3 {
		t.Fatal("untrusted TLS request reached API handler")
	}
}

func TestSubstrateDeleteRequiresExactScopeUIDAndResourceVersion(t *testing.T) {
	var calls atomic.Int32
	client, profile, _ := testAPIClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodDelete {
			t.Error("unexpected method")
		}
		var value map[string]any
		if json.NewDecoder(request.Body).Decode(&value) != nil {
			t.Error("invalid delete payload")
		}
		preconditions := nested(value, "preconditions")
		if stringField(preconditions, "uid") != "11111111-1111-4111-8111-111111111111" || stringField(preconditions, "resourceVersion") != "123" || stringField(value, "propagationPolicy") != "Foreground" {
			t.Error("delete guard missing")
		}
		_, _ = writer.Write([]byte(`{"kind":"Status"}`))
	}))
	plan, _ := BuildPlan(profile)
	ref := plan.Objects[0]
	if err := client.delete(context.Background(), ref, "123"); !errors.Is(err, ErrConflict) {
		t.Fatal("missing UID accepted")
	}
	ref.UID = "11111111-1111-4111-8111-111111111111"
	if err := client.delete(context.Background(), ref, ""); !errors.Is(err, ErrConflict) {
		t.Fatal("missing revision accepted")
	}
	foreign := ref
	foreign.Name = "production"
	if err := client.delete(context.Background(), foreign, "123"); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign scope accepted")
	}
	if err := client.delete(context.Background(), ref, "123"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("unsafe delete reached API")
	}
}

func TestSubstrateCancellationStopsRequest(t *testing.T) {
	entered := make(chan struct{})
	client, _, _ := testAPIClient(t, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) { close(entered); <-request.Context().Done() }))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.request(ctx, http.MethodGet, "/wait", url.Values{}, nil, new(any)) }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled request did not stop")
	}
}

func TestResourceAccountingAndNetworkBoundary(t *testing.T) {
	for value, expected := range map[string]int64{"1": 1000, "1500m": 1500, "8Gi": 8 * (1 << 30) * 1000, "1.5Mi": 1536 * 1024 * 1000, "0.00001": 1} {
		actual, err := quantityMilli(value)
		if err != nil || actual != expected {
			t.Fatalf("quantity %s: %d %v", value, actual, err)
		}
	}
	for _, value := range []string{"-1", "NaN", "1Ei", "1E99999", "", "../1"} {
		if _, err := quantityMilli(value); err == nil {
			t.Fatalf("unsafe resource quantity %q", value)
		}
	}
	profile := testProfile()
	if networkSeparated(profile, ipv4Prefix([4]byte{172, 30, 99}, 24)) || networkSeparated(profile, ipv4Prefix([4]byte{192, 168, 234, 2}, 32)) || !networkSeparated(profile, ipv4Prefix([4]byte{10, 42}, 16)) {
		t.Fatal("network overlap guard incorrect")
	}
	pod := apiObject{"spec": map[string]any{"containers": []any{map[string]any{"resources": map[string]any{"requests": map[string]any{"cpu": "1", "memory": "1Gi"}}}}, "initContainers": []any{map[string]any{"resources": map[string]any{"requests": map[string]any{"cpu": "2", "memory": "2Gi"}}}}, "overhead": map[string]any{"cpu": "100m", "memory": "128Mi"}}}
	cpu, memory, err := podRequests(pod)
	if err != nil || cpu != 3100 || memory != (3*(1<<30)+128*(1<<20))*1000 {
		t.Fatalf("parent pod reservation understated: %d %d %v", cpu, memory, err)
	}
}

// TestSubstrateCancellationAtResponseBoundary deterministically exercises the
// timing seen in PR161 CI without relying on HTTP scheduling or sleeps.
func TestSubstrateCancellationAtResponseBoundary(t *testing.T) {
	for _, stage := range []string{"headers", "body-eof", "body-error", "body-valid-json"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body := &cancelAPIResponseBody{reader: strings.NewReader(""), cancel: cancel}
			if stage == "body-error" {
				body.readError = errors.New("synthetic body interruption")
			}
			if stage == "body-valid-json" {
				body.reader = strings.NewReader(`{"verified":true}`)
			}
			client := &Client{profile: testProfile(), http: &http.Client{Transport: apiResponseTransport(func(request *http.Request) (*http.Response, error) {
				if stage == "headers" {
					cancel()
				}
				return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header), Request: request}, nil
			})}}
			err := client.request(ctx, http.MethodGet, "/cancel-boundary", nil, nil, new(any))
			if !body.closed {
				t.Fatal("cancelled response body was not closed")
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost at %s: %v", stage, err)
			}
		})
	}
}

type apiResponseTransport func(*http.Request) (*http.Response, error)

func (transport apiResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

type cancelAPIResponseBody struct {
	reader    io.Reader
	cancel    context.CancelFunc
	readError error
	closed    bool
}

func (body *cancelAPIResponseBody) Read(output []byte) (int, error) {
	body.cancel()
	if body.readError != nil {
		return 0, body.readError
	}
	return body.reader.Read(output)
}

func (body *cancelAPIResponseBody) Close() error {
	body.closed = true
	return nil
}
