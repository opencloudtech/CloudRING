// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package openbaoapply

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/openbaoauth"
)

func validRequest(t *testing.T) Request {
	t.Helper()
	request := Request{
		SchemaVersion: SchemaVersion,
		Contract: openbaoauth.Contract{
			SchemaVersion: openbaoauth.SchemaVersion, AuthMount: "kubernetes-consumer-example",
			AuthMountOwnership: openbaoauth.DedicatedAuthMountOwnership, KVV2Mount: "cloudring",
			DataPrefix: "services/consumer-example", PolicyName: "consumer-example-kv-read", RoleName: "consumer-example",
			WorkloadIdentity: openbaoauth.WorkloadIdentity{Namespace: "consumer-example", ServiceAccount: "consumer-reader"},
			Audience:         "openbao", AliasNameSource: "serviceaccount_uid", TokenTTL: "10m", TokenMaxTTL: "30m", TokenNoDefaultPolicy: true,
		},
		OpenBao:              Connection{Address: "https://openbao.example.test", ServerName: "openbao.example.test", CACertificateBase64: encode("ca")},
		Kubernetes:           Connection{Address: "https://kubernetes.example.test", ServerName: "kubernetes.example.test", CACertificateBase64: encode("ca")},
		Lease:                LeaseTarget{Namespace: "cloudring-system", Name: "openbao-bootstrap", HolderIdentity: "executor-0123456789"},
		ExecutorIdentity:     WorkloadIdentity{Namespace: "cloudring-system", ServiceAccount: "openbao-bootstrap-executor"},
		ManagementPolicyName: "consumer-bootstrap",
		ManagementAccessor:   "management-accessor",
		WrappingTokenBase64:  encode("wrapping-token"),
		Seed:                 Seed{RelativePath: "cloud-credentials", Entries: []SecretEntry{{Key: "cloud", ValueBase64: encode("secret-value")}}},
		NegativeIdentities: NegativeIdentities{
			WrongServiceAccount: WorkloadIdentity{Namespace: "consumer-example", ServiceAccount: "consumer-denied"},
			WrongNamespace:      WorkloadIdentity{Namespace: "consumer-denied", ServiceAccount: "consumer-reader"},
		},
		Approval: Approval{ChangeAuthorized: true},
	}
	request.ExecutorServiceAccountUID = "executor-service-account-uid"
	request.Kubernetes.BearerTokenBase64 = encode(executorJWT(request.ExecutorIdentity, request.ExecutorServiceAccountUID, time.Now().Add(10*time.Minute)))
	binding, err := BindingSHA256(request)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	request.Approval.BindingSHA256 = binding
	return request
}

func TestParseAcceptsExactBoundRequest(t *testing.T) {
	request := validRequest(t)
	data, _ := json.Marshal(request)
	parsed, gate, err := Parse(bytes.NewReader(data))
	if err != nil || gate != "" || parsed.Contract.RoleName != request.Contract.RoleName {
		t.Fatalf("Parse() gate=%q err=%v", gate, err)
	}
}

func TestParseFailsClosedWithoutReflectingCredentials(t *testing.T) {
	request := validRequest(t)
	request.Seed.Entries[0].ValueBase64 = encode("changed-secret")
	data, _ := json.Marshal(request)
	_, gate, err := Parse(bytes.NewReader(data))
	if err != nil || gate != "approval-binding" || strings.Contains(gate, "changed-secret") {
		t.Fatalf("Parse() gate=%q err=%v", gate, err)
	}
}

func TestBindingIncludesBothTrustRoots(t *testing.T) {
	request := validRequest(t)
	request.OpenBao.CACertificateBase64 = encode("different-ca")
	data, _ := json.Marshal(request)
	if _, gate, _ := Parse(bytes.NewReader(data)); gate != "approval-binding" {
		t.Fatalf("changed CA root gate=%q", gate)
	}
}

func TestParseRejectsNonUTF8SecretValue(t *testing.T) {
	request := validRequest(t)
	request.Seed.Entries[0].ValueBase64 = base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe})
	binding, _ := BindingSHA256(request)
	request.Approval.BindingSHA256 = binding
	data, _ := json.Marshal(request)
	if _, gate, _ := Parse(bytes.NewReader(data)); gate != "seed-contract" {
		t.Fatalf("non-UTF8 seed gate=%q", gate)
	}
}

func TestParseRequiresDedicatedExecutorIdentity(t *testing.T) {
	request := validRequest(t)
	request.ExecutorIdentity = WorkloadIdentity{Namespace: request.Contract.WorkloadIdentity.Namespace, ServiceAccount: request.Contract.WorkloadIdentity.ServiceAccount}
	request.Kubernetes.BearerTokenBase64 = encode(executorJWT(request.ExecutorIdentity, request.ExecutorServiceAccountUID, time.Now().Add(10*time.Minute)))
	binding, _ := BindingSHA256(request)
	request.Approval.BindingSHA256 = binding
	data, _ := json.Marshal(request)
	if _, gate, _ := Parse(bytes.NewReader(data)); gate != "executor-identity-separation" {
		t.Fatalf("shared executor identity gate=%q", gate)
	}
}

func TestParseRejectsUnboundedOrMismatchedExecutorJWT(t *testing.T) {
	tests := []struct {
		name    string
		expires time.Time
		edit    func(*Request)
	}{
		{name: "expired", expires: time.Now().Add(-time.Minute)},
		{name: "too long", expires: time.Now().Add(16 * time.Minute)},
		{name: "wrong subject", expires: time.Now().Add(10 * time.Minute), edit: func(request *Request) {
			request.ExecutorIdentity.ServiceAccount = "different-executor"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest(t)
			request.Kubernetes.BearerTokenBase64 = encode(executorJWT(request.ExecutorIdentity, request.ExecutorServiceAccountUID, test.expires))
			if test.edit != nil {
				test.edit(&request)
			}
			binding, _ := BindingSHA256(request)
			request.Approval.BindingSHA256 = binding
			data, _ := json.Marshal(request)
			if _, gate, _ := Parse(bytes.NewReader(data)); gate != "executor-token-contract" {
				t.Fatalf("gate=%q", gate)
			}
		})
	}
}

func TestParseRejectsDuplicateNestedFieldAndInsecureTarget(t *testing.T) {
	request := validRequest(t)
	data, _ := json.Marshal(request)
	duplicate := bytes.Replace(data, []byte(`"relativePath":"cloud-credentials"`), []byte(`"relativePath":"cloud-credentials","relativePath":"second"`), 1)
	if _, gate, _ := Parse(bytes.NewReader(duplicate)); gate != "duplicate-field" {
		t.Fatalf("duplicate gate=%q", gate)
	}
	request = validRequest(t)
	request.OpenBao.Address = "http://openbao.example.test"
	binding, _ := BindingSHA256(request)
	request.Approval.BindingSHA256 = binding
	data, _ = json.Marshal(request)
	if _, gate, _ := Parse(bytes.NewReader(data)); gate != "secure-connection-contract" {
		t.Fatalf("insecure target gate=%q", gate)
	}
}

func TestParseBoundsInput(t *testing.T) {
	_, gate, err := Parse(strings.NewReader(strings.Repeat("x", MaxInputBytes+1)))
	if err != nil || gate != "input-too-large" {
		t.Fatalf("Parse() gate=%q err=%v", gate, err)
	}
}

func encode(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }

func executorJWT(identity WorkloadIdentity, uid string, expires time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
		"aud": []string{"kubernetes"}, "exp": expires.Unix(),
		"sub": "system:serviceaccount:" + identity.Namespace + ":" + identity.ServiceAccount,
		"kubernetes.io": map[string]any{
			"namespace":      identity.Namespace,
			"serviceaccount": map[string]any{"name": identity.ServiceAccount, "uid": uid},
		},
	})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}
