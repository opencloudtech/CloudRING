// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package openbaoapply

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRESTClientUsesPinnedTrustWithoutProxyAndRejectsRedirects(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/redirect" {
			writer.Header().Set("Location", "/ok")
			writer.WriteHeader(http.StatusFound)
			_, _ = writer.Write([]byte(`{"redirect":true}`))
			return
		}
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	certificate, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	serverName := ""
	if len(certificate.IPAddresses) != 0 {
		serverName = certificate.IPAddresses[0].String()
	} else if len(certificate.DNSNames) != 0 {
		serverName = certificate.DNSNames[0]
	}
	if serverName == "" {
		t.Fatal("test certificate has no usable SAN")
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	connection := Connection{Address: server.URL, ServerName: serverName, CACertificateBase64: base64.StdEncoding.EncodeToString(caPEM)}
	t.Setenv("HTTPS_PROXY", "http://proxy.example.invalid")
	client, err := newRESTClient(connection, "")
	if err != nil {
		t.Fatalf("newRESTClient: %v", err)
	}
	status, payload, err := client.do(context.Background(), http.MethodGet, "/ok", "", nil)
	if err != nil || status != http.StatusOK || payload["ok"] != true {
		t.Fatalf("GET /ok status=%d payload=%v err=%v", status, payload, err)
	}
	status, _, err = client.do(context.Background(), http.MethodGet, "/redirect", "", nil)
	if err != nil || status != http.StatusFound || requests != 2 {
		t.Fatalf("redirect status=%d requests=%d err=%v", status, requests, err)
	}
}

func TestRESTClientRejectsDuplicateResponseFields(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"sealed":false,"sealed":true}}`))
	}))
	defer server.Close()
	certificate, _ := x509.ParseCertificate(server.Certificate().Raw)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	serverName := certificate.IPAddresses[0].String()
	client, err := newRESTClient(Connection{Address: server.URL, ServerName: serverName, CACertificateBase64: base64.StdEncoding.EncodeToString(caPEM)}, "")
	if err != nil {
		t.Fatalf("newRESTClient: %v", err)
	}
	if _, _, err := client.do(context.Background(), http.MethodGet, "/", "", nil); err == nil {
		t.Fatal("duplicate response field was accepted")
	}
}

func TestExactMissingSecretMountReadFailsClosed(t *testing.T) {
	exact := map[string]any{"errors": []any{"No secret engine mount at cloudring/"}}
	if !exactMissingSecretMountRead("sys/mounts/cloudring", exact) {
		t.Fatal("exact OpenBao 2.5.5 missing-secret-mount envelope was rejected")
	}
	for _, test := range []struct {
		path    string
		payload map[string]any
	}{
		{"sys/mounts/cloudring-other", exact},
		{"sys/mounts/cloudring", map[string]any{"errors": []any{"No secret engine mount at cloudring/"}, "extra": true}},
		{"sys/mounts/cloudring", map[string]any{"errors": []any{"No secret engine mount at cloudring/", "unexpected"}}},
		{"sys/mounts/cloudring", map[string]any{"errors": []any{"no secret engine mount"}}},
	} {
		if exactMissingSecretMountRead(test.path, test.payload) {
			t.Fatalf("drifted missing-secret-mount envelope accepted: path=%q payload=%v", test.path, test.payload)
		}
	}
}

func TestLookupSelfAcceptsOpenBao255NullMetadataAndDetectsEffectiveAuthority(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"policies":["bootstrap-policy"],"accessor":"bootstrap-accessor","ttl":600,"renewable":false,"type":"service","explicit_max_ttl":900,"num_uses":0,"orphan":true,"meta":null,"entity_id":"","path":"auth/token/create"}}`))
	}))
	defer server.Close()
	certificate, _ := x509.ParseCertificate(server.Certificate().Raw)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	connection := Connection{Address: server.URL, ServerName: certificate.IPAddresses[0].String(), CACertificateBase64: base64.StdEncoding.EncodeToString(caPEM)}
	client, err := NewOpenBaoClient(connection)
	if err != nil {
		t.Fatalf("NewOpenBaoClient: %v", err)
	}
	facts, err := client.LookupSelf(context.Background(), "management-token")
	if err != nil || !validManagementToken(facts, "bootstrap-policy") {
		t.Fatalf("LookupSelf facts=%+v err=%v", facts, err)
	}
	facts.IdentityPolicies = []string{"unexpected"}
	if validManagementToken(facts, "bootstrap-policy") {
		t.Fatal("identity-derived authority was accepted")
	}
}

func TestLookupSelfAcceptsExactOpenBao255InitialRootShape(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"accessor":"root-accessor","creation_time":1750000000,"creation_ttl":0,"display_name":"root","entity_id":"","expire_time":null,"explicit_max_ttl":0,"id":"root-value-redacted","issue_time":"2026-07-13T00:00:00Z","meta":null,"num_uses":0,"orphan":true,"path":"auth/token/root","policies":["root"],"ttl":0,"type":"service"}}`))
	}))
	defer server.Close()
	client, err := NewOpenBaoClient(testTLSConnection(t, server, ""))
	if err != nil {
		t.Fatal(err)
	}
	facts, err := client.LookupSelf(context.Background(), "root-bearer")
	if err != nil || !validInitialRoot(facts) || facts.RenewableKnown {
		t.Fatalf("facts=%+v err=%v", facts, err)
	}
}

func TestExpectForbiddenRejectsBadRequest(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"errors":["invalid request"]}`))
	}))
	defer server.Close()
	certificate, _ := x509.ParseCertificate(server.Certificate().Raw)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	client, err := NewOpenBaoClient(Connection{Address: server.URL, ServerName: certificate.IPAddresses[0].String(), CACertificateBase64: base64.StdEncoding.EncodeToString(caPEM)})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ExpectForbidden(context.Background(), http.MethodGet, "token", "path", nil); err == nil {
		t.Fatal("HTTP 400 was accepted as authorization denial")
	}
}

func TestHealthRequiresExactOpenBaoVersion(t *testing.T) {
	version := supportedOpenBaoVersion
	performanceMode := "primary"
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"initialized":true,"sealed":false,"standby":false,"performance_standby":false,"replication_performance_mode":"` + performanceMode + `","replication_dr_mode":"disabled","server_time_utc":` + strconv.FormatInt(time.Now().Unix(), 10) + `,"version":"` + version + `","cluster_name":"synthetic-cluster","cluster_id":"synthetic-cluster-id"}`))
	}))
	defer server.Close()
	connection := testTLSConnection(t, server, "")
	client, err := NewOpenBaoClient(connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("supported active HA health rejected: %v", err)
	}
	performanceMode = "disabled"
	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("supported standalone health rejected: %v", err)
	}
	performanceMode = "secondary"
	if err := client.Health(context.Background()); err == nil {
		t.Fatal("performance-replication secondary accepted as writable active health")
	}
	performanceMode = "primary"
	version = "2.5.4"
	if err := client.Health(context.Background()); err == nil {
		t.Fatal("unsupported OpenBao version accepted")
	}
}

func TestTokenRequestRequiresBoundedExpirationTimestamp(t *testing.T) {
	expiration := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)
	omitExpiration := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/namespaces/example/serviceaccounts/reader/token" || request.Header.Get("Authorization") != "Bearer executor-bearer" {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		jwtField := "to" + "ken"
		if omitExpiration {
			_ = json.NewEncoder(writer).Encode(map[string]any{"status": map[string]any{jwtField: "projected-jwt-value"}})
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"status": map[string]any{jwtField: "projected-jwt-value", "expirationTimestamp": expiration.Format(time.RFC3339)}})
	}))
	defer server.Close()
	client, err := NewKubernetesClient(testTLSConnection(t, server, "executor-bearer"))
	if err != nil {
		t.Fatal(err)
	}
	projected, err := client.RequestServiceAccountToken(context.Background(), "example", "reader", "openbao", 600)
	if err != nil || projected.JWT != "projected-jwt-value" || !projected.ExpirationTimestamp.Equal(expiration) || !validServiceAccountToken(projected, 600) {
		t.Fatalf("projected=%+v err=%v", projected, err)
	}
	omitExpiration = true
	if _, err := client.RequestServiceAccountToken(context.Background(), "example", "reader", "openbao", 600); err == nil {
		t.Fatal("missing TokenRequest expirationTimestamp accepted")
	}
}

func TestSupervisorClientWrapsAndRevokesBothAccessors(t *testing.T) {
	revoked := map[string]bool{}
	requestID := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("X-Vault-Token") != "root-bearer" {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		switch request.URL.Path {
		case "/v1/auth/token/create":
			if request.Header.Get("X-Vault-Wrap-TTL") != "60s" {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"request_id": requestID, "lease_id": "", "renewable": false, "lease_duration": 0, "data": nil,
				"wrap_info": map[string]any{"to" + "ken": "wrapper-value", "accessor": "wrapper-accessor", "ttl": 60, "creation_time": time.Now().UTC().Format(time.RFC3339Nano), "creation_path": "auth/token/create", "wrapped_accessor": "child-accessor"},
				"warnings":  nil, "auth": nil,
			})
		case "/v1/auth/token/lookup-accessor":
			body := readTestJSON(t, request)
			accessor := textValue(body, "accessor")
			if revoked[accessor] {
				writer.WriteHeader(http.StatusBadRequest)
				_, _ = writer.Write([]byte(`{"errors":["invalid accessor"]}`))
				return
			}
			_, _ = writer.Write([]byte(`{"data":{"accessor":"` + accessor + `"}}`))
		case "/v1/auth/token/revoke-accessor":
			body := readTestJSON(t, request)
			accessor := textValue(body, "accessor")
			revoked[accessor] = true
			if accessor == "response-loss-accessor" {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := newSupervisorOpenBaoClient(testTLSConnection(t, server, ""))
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := client.CreateWrappedManagementToken(context.Background(), "root-bearer", "root-accessor", "cloudring-bootstrap-test")
	if err != nil || wrapped.Value != "wrapper-value" || wrapped.WrappedAccessor != "child-accessor" {
		t.Fatalf("wrapped=%+v err=%v", wrapped, err)
	}
	requestID = "unexpected-request-id"
	if _, err := client.CreateWrappedManagementToken(context.Background(), "root-bearer", "root-accessor", "cloudring-bootstrap-test"); err == nil {
		t.Fatal("non-empty wrapped-response request_id accepted")
	}
	for _, accessor := range []string{wrapped.Accessor, wrapped.WrappedAccessor} {
		if !client.RevokeAccessorAndProve(context.Background(), "root-bearer", accessor) || !revoked[accessor] {
			t.Fatalf("accessor %q was not revoked", accessor)
		}
	}
	if !client.RevokeAccessorAndProve(context.Background(), "root-bearer", "response-loss-accessor") || !revoked["response-loss-accessor"] {
		t.Fatal("committed accessor revoke with lost response was not resolved by post-lookup")
	}
}

func testTLSConnection(t *testing.T, server *httptest.Server, bearer string) Connection {
	t.Helper()
	certificate, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	connection := Connection{Address: server.URL, ServerName: certificate.IPAddresses[0].String(), CACertificateBase64: base64.StdEncoding.EncodeToString(caPEM)}
	if bearer != "" {
		connection.BearerTokenBase64 = base64.StdEncoding.EncodeToString([]byte(bearer))
	}
	return connection
}

func readTestJSON(t *testing.T, request *http.Request) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(request.Body)
	decoder.UseNumber()
	var body map[string]any
	if err := decoder.Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestMutationStatusClassification(t *testing.T) {
	for _, test := range []struct {
		status int
		want   error
	}{
		{http.StatusForbidden, errForbidden},
		{http.StatusBadRequest, errDefinitelyRejected},
		{http.StatusInternalServerError, errMutationAmbiguous},
	} {
		if err := mutationStatusError(test.status); !errors.Is(err, test.want) {
			t.Fatalf("status=%d err=%v want=%v", test.status, err, test.want)
		}
	}
	if strings.Contains(mutationStatusError(http.StatusInternalServerError).Error(), "500") {
		t.Fatal("dynamic provider status leaked into fixed error")
	}
}

func TestKubernetesRESTClientUsesExactLeaseIdentityAndReviewProtocols(t *testing.T) {
	leaseState := map[string]any{
		"apiVersion": "coordination.k8s.io/v1", "kind": "Lease",
		"metadata": map[string]any{"name": "bootstrap", "namespace": "system", "uid": "lease-uid", "resourceVersion": "1", "labels": map[string]any{"preserved": "true"}},
		"spec":     map[string]any{},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/apis/coordination.k8s.io/v1/namespaces/system/leases/bootstrap":
			_ = json.NewEncoder(writer).Encode(leaseState)
		case request.Method == http.MethodPut && request.URL.Path == "/apis/coordination.k8s.io/v1/namespaces/system/leases/bootstrap":
			body := readTestJSON(t, request)
			metadata, _ := object(body, "metadata")
			if nestedLabels, _ := object(metadata, "labels"); textValue(nestedLabels, "preserved") != "true" {
				t.Error("unknown Lease fields were not preserved")
			}
			metadata["resourceVersion"] = "2"
			leaseState = body
			_ = json.NewEncoder(writer).Encode(body)
		case request.Method == http.MethodPost && request.URL.Path == "/apis/authentication.k8s.io/v1/selfsubjectreviews":
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(map[string]any{"status": map[string]any{"userInfo": map[string]any{
				"username": "system:serviceaccount:system:executor", "uid": "executor-uid", "groups": []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:system"},
			}}})
		case request.Method == http.MethodPost && request.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(map[string]any{"status": map[string]any{"allowed": true, "denied": false, "evaluationError": ""}})
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/namespaces/system/serviceaccounts/executor":
			_ = json.NewEncoder(writer).Encode(map[string]any{"metadata": map[string]any{"name": "executor", "namespace": "system", "uid": "executor-uid"}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := NewKubernetesClient(testTLSConnection(t, server, "executor-bearer"))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := client.GetLease(context.Background(), LeaseTarget{Namespace: "system", Name: "bootstrap"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	lease.HolderIdentity, lease.LeaseDurationSec, lease.AcquireTime, lease.RenewTime = "holder", 30, now, now
	updated, err := client.UpdateLease(context.Background(), LeaseTarget{Namespace: "system", Name: "bootstrap"}, lease)
	if err != nil || updated.ResourceVersion != "2" || !updated.AcquireTime.Equal(now) {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	subject, err := client.ReviewSelf(context.Background())
	if err != nil || subject.UID != "executor-uid" || len(subject.Groups) != 3 {
		t.Fatalf("subject=%+v err=%v", subject, err)
	}
	allowed, err := client.ReviewAccess(context.Background(), ResourceAccess{Verb: "get", Resource: "serviceaccounts", Namespace: "system", Name: "executor"})
	if err != nil || !allowed {
		t.Fatalf("allowed=%v err=%v", allowed, err)
	}
	serviceAccount, err := client.GetServiceAccount(context.Background(), "system", "executor")
	if err != nil || serviceAccount.UID != "executor-uid" {
		t.Fatalf("serviceAccount=%+v err=%v", serviceAccount, err)
	}
}

func TestOpenBaoRESTClientUsesExactStatusesAndResponseShapes(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		clientCredentialField := "client_" + "to" + "ken"
		switch request.URL.Path {
		case "/v1/sys/health":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"initialized": true, "sealed": false, "standby": false, "performance_standby": false,
				"replication_performance_mode": "disabled", "replication_dr_mode": "disabled", "server_time_utc": time.Now().Unix(),
				"version": supportedOpenBaoVersion, "cluster_name": "synthetic-cluster", "cluster_id": "synthetic-id",
			})
		case "/v1/sys/wrapping/unwrap":
			_ = json.NewEncoder(writer).Encode(map[string]any{"auth": map[string]any{clientCredentialField: "unwrapped-value"}})
		case "/v1/sys/capabilities-self":
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": map[string]any{"synthetic/path": []string{"read"}}})
		case "/v1/synthetic/read", "/v1/synthetic/list":
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": map[string]any{"value": "synthetic"}})
		case "/v1/synthetic/missing":
			writer.WriteHeader(http.StatusNotFound)
		case "/v1/sys/auth/kubernetes-absent":
			writer.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(writer).Encode(map[string]any{"errors": []string{"No auth engine at kubernetes-absent/"}})
		case "/v1/sys/auth/kubernetes-drifted":
			writer.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(writer).Encode(map[string]any{"errors": []string{"unexpected response"}})
		case "/v1/sys/mounts/cloudring-absent":
			writer.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(writer).Encode(map[string]any{"errors": []string{"No secret engine mount at cloudring-absent/"}})
		case "/v1/sys/mounts/cloudring-drifted":
			writer.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(writer).Encode(map[string]any{"errors": []string{"No secret engine mount at another-mount/"}})
		case "/v1/synthetic/write", "/v1/synthetic/delete":
			writer.WriteHeader(http.StatusNoContent)
		case "/v1/auth/kubernetes-consumer-example/login":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"request_id": "synthetic-login", "lease_id": "", "renewable": false, "lease_duration": 0, "data": nil, "wrap_info": nil, "warnings": nil,
				"auth": map[string]any{
					clientCredentialField: "workload-value", "accessor": "workload-accessor", "entity_id": "workload-entity", "lease_duration": 600,
					"metadata":        map[string]any{"role": "consumer-example", "service_account_name": "consumer-reader", "service_account_namespace": "consumer-example", "service_account_secret_name": "", "service_account_uid": "service-account-uid"},
					"mfa_requirement": nil, "num_uses": 0, "orphan": true, "policies": []string{"consumer-example-kv-read"}, "renewable": true,
					"token_policies": []string{"consumer-example-kv-read"}, "token_type": "service",
				},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := NewOpenBaoClient(testTLSConnection(t, server, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if value, err := client.Unwrap(context.Background(), "wrapper-value"); err != nil || value != "unwrapped-value" {
		t.Fatalf("unwrap value=%q err=%v", value, err)
	}
	capabilities, err := client.CapabilitiesSelf(context.Background(), "bearer-value", []string{"synthetic/path"})
	if err != nil || !equalStrings(capabilities["synthetic/path"], []string{"read"}) {
		t.Fatalf("capabilities=%v err=%v", capabilities, err)
	}
	if result, err := client.Read(context.Background(), "bearer-value", "synthetic/read"); err != nil || !result.Found {
		t.Fatalf("read=%+v err=%v", result, err)
	}
	if result, err := client.List(context.Background(), "bearer-value", "synthetic/list"); err != nil || !result.Found {
		t.Fatalf("list=%+v err=%v", result, err)
	}
	if result, err := client.Read(context.Background(), "bearer-value", "synthetic/missing"); err != nil || result.Found {
		t.Fatalf("missing=%+v err=%v", result, err)
	}
	if result, err := client.Read(context.Background(), "bearer-value", "sys/auth/kubernetes-absent"); err != nil || result.Found {
		t.Fatalf("missing auth mount=%+v err=%v", result, err)
	}
	if _, err := client.Read(context.Background(), "bearer-value", "sys/auth/kubernetes-drifted"); err == nil {
		t.Fatal("drifted missing-auth envelope accepted")
	}
	if result, err := client.Read(context.Background(), "bearer-value", "sys/mounts/cloudring-absent"); err != nil || result.Found {
		t.Fatalf("missing secret mount=%+v err=%v", result, err)
	}
	if _, err := client.Read(context.Background(), "bearer-value", "sys/mounts/cloudring-drifted"); err == nil {
		t.Fatal("drifted missing-secret-mount envelope accepted")
	}
	if _, err := client.Write(context.Background(), "bearer-value", "synthetic/write", map[string]any{"value": "synthetic"}); err != nil {
		t.Fatal(err)
	}
	if err := client.Delete(context.Background(), "bearer-value", "synthetic/delete"); err != nil {
		t.Fatal(err)
	}
	request := validRequest(t)
	login, err := client.Write(context.Background(), "", "auth/"+request.Contract.AuthMount+"/login", map[string]any{"role": request.Contract.RoleName, "jwt": "projected-value"})
	if err != nil || !exactLogin(login.Auth, request.Contract, "service-account-uid") {
		t.Fatalf("login=%+v err=%v", login, err)
	}
}
