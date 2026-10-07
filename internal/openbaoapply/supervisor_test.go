// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package openbaoapply

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/openbaobootstrap"
)

func TestExecuteSupervisedAppliesAndRemovesTemporaryAuthority(t *testing.T) {
	input := validSupervisorRequest(t)
	policyName := "cloudring-bootstrap-supervised"
	applyRequest, gate := assembleSupervisedRequest(input, policyName, "validation-wrapper", "child-accessor")
	if gate != "" {
		t.Fatal(gate)
	}
	kubernetes := newFakeKubernetes(applyRequest)
	openBao := newFakeOpenBao(applyRequest)
	openBao.temporaryPolicy = false
	report := executeSupervised(context.Background(), input, policyName, kubernetes, openBao)
	if report.Status != StatusApplied || report.FailedGate != "" || openBao.temporaryPolicy || !openBao.wrapperAccessorRevoked || !openBao.childAccessorRevoked || openBao.rootTargetMutation {
		t.Fatalf("report=%+v temporary=%v wrapper=%v child=%v rootTarget=%v", report, openBao.temporaryPolicy, openBao.wrapperAccessorRevoked, openBao.childAccessorRevoked, openBao.rootTargetMutation)
	}
	if !containsString(report.CompletedGates, "supervisor-authority-cleanup") {
		t.Fatalf("cleanup gate absent: %+v", report.CompletedGates)
	}
}

func TestExecuteSupervisedFailsClosedAndCleansPolicyWhenWrapIsAmbiguous(t *testing.T) {
	input := validSupervisorRequest(t)
	policyName := "cloudring-bootstrap-wrap-failure"
	applyRequest, _ := assembleSupervisedRequest(input, policyName, "validation-wrapper", "child-accessor")
	openBao := newFakeOpenBao(applyRequest)
	openBao.temporaryPolicy = false
	openBao.failWrappedCreate = true
	report := executeSupervised(context.Background(), input, policyName, newFakeKubernetes(applyRequest), openBao)
	if report.Status != StatusPartialManualInterventionRequired || report.FailedGate != "wrapped-delegation-create" || openBao.temporaryPolicy || !report.RollbackAttempted {
		t.Fatalf("report=%+v temporary=%v", report, openBao.temporaryPolicy)
	}
}

func TestExecuteSupervisedMapsDefiniteWrapRejectionToRolledBack(t *testing.T) {
	input := validSupervisorRequest(t)
	policyName := "cloudring-bootstrap-wrap-rejected"
	applyRequest, _ := assembleSupervisedRequest(input, policyName, "validation-wrapper", "child-accessor")
	openBao := newFakeOpenBao(applyRequest)
	openBao.temporaryPolicy = false
	openBao.wrappedCreateError = errDefinitelyRejected
	report := executeSupervised(context.Background(), input, policyName, newFakeKubernetes(applyRequest), openBao)
	if report.Status != StatusRolledBack || report.FailedGate != "wrapped-delegation-create" || openBao.temporaryPolicy || !report.MutationPerformed || !report.RollbackAttempted {
		t.Fatalf("report=%+v temporary=%v", report, openBao.temporaryPolicy)
	}
}

func TestExecuteSupervisedRejectsNonExactRootWithoutMutation(t *testing.T) {
	input := validSupervisorRequest(t)
	policyName := "cloudring-bootstrap-root-rejected"
	applyRequest, _ := assembleSupervisedRequest(input, policyName, "validation-wrapper", "child-accessor")
	openBao := newFakeOpenBao(applyRequest)
	openBao.temporaryPolicy = false
	openBao.invalidInitialRoot = true
	report := executeSupervised(context.Background(), input, policyName, newFakeKubernetes(applyRequest), openBao)
	if report.Status != StatusBlockedPreflight || report.MutationPerformed || report.FailedGate != "initial-root-profile" || openBao.temporaryPolicy {
		t.Fatalf("report=%+v temporary=%v", report, openBao.temporaryPolicy)
	}
}

func TestExecuteSupervisedMakesCleanupFailureManual(t *testing.T) {
	input := validSupervisorRequest(t)
	policyName := "cloudring-bootstrap-cleanup-failure"
	applyRequest, _ := assembleSupervisedRequest(input, policyName, "validation-wrapper", "child-accessor")
	openBao := newFakeOpenBao(applyRequest)
	openBao.temporaryPolicy = false
	openBao.failSupervisorCleanup = true
	report := executeSupervised(context.Background(), input, policyName, newFakeKubernetes(applyRequest), openBao)
	if report.Status != StatusPartialManualInterventionRequired || report.FailedGate != "supervisor-cleanup" {
		t.Fatalf("report=%+v", report)
	}
}

func TestExecuteSupervisedMapsCleanedApplyPreflightBlockToRolledBack(t *testing.T) {
	input := validSupervisorRequest(t)
	policyName := "cloudring-bootstrap-apply-blocked"
	applyRequest, _ := assembleSupervisedRequest(input, policyName, "validation-wrapper", "child-accessor")
	kubernetes := newFakeKubernetes(applyRequest)
	kubernetes.allowAll = true
	openBao := newFakeOpenBao(applyRequest)
	openBao.temporaryPolicy = false
	report := executeSupervised(context.Background(), input, policyName, kubernetes, openBao)
	if report.Status != StatusRolledBack || !report.MutationPerformed || !report.RollbackAttempted || openBao.temporaryPolicy || !openBao.wrapperAccessorRevoked || !openBao.childAccessorRevoked {
		t.Fatalf("report=%+v temporary=%v", report, openBao.temporaryPolicy)
	}
}

func TestTemporaryPolicyOwnershipRequiresVersionOneAndStableModified(t *testing.T) {
	result := ReadResult{Found: true, Data: map[string]any{
		"name": "cloudring-bootstrap-owned", "policy": "path \"x\" {}\n", "cas_required": false, "version": json.Number("1"), "modified": fakeSeedCreatedAt,
	}}
	modified, exact := temporaryPolicyCreated(result, "cloudring-bootstrap-owned", "path \"x\" {}\n")
	if !exact || modified != fakeSeedCreatedAt {
		t.Fatal("exact version-one policy rejected")
	}
	result.Data["version"] = json.Number("2")
	if _, exact := temporaryPolicyCreated(result, "cloudring-bootstrap-owned", "path \"x\" {}\n"); exact {
		t.Fatal("version-two temporary policy adopted")
	}
}

func TestTemporaryPolicyCleanupResolvesCommittedDeleteWithLostResponse(t *testing.T) {
	input := validSupervisorRequest(t)
	policyName := "cloudring-bootstrap-delete-response-lost"
	applyRequest, _ := assembleSupervisedRequest(input, policyName, "validation-wrapper", "child-accessor")
	openBao := newFakeOpenBao(applyRequest)
	openBao.policyDeleteResponseLost = true
	delegation, _ := openbaobootstrap.BuildManagementDelegation(input.Contract, policyName, input.Seed.RelativePath)
	ownership := temporaryPolicyOwnership{name: policyName, body: delegation.Body, modified: fakeSeedCreatedAt}
	if !cleanupTemporaryPolicy(context.Background(), openBao, "root-bearer", ownership) || openBao.temporaryPolicy {
		t.Fatal("committed policy delete with lost response was not resolved by post-read")
	}
}

func TestParseSupervisorRequestIsStrictAndDoesNotReflectRootMaterial(t *testing.T) {
	input := validSupervisorRequest(t)
	encoded, _ := json.Marshal(input)
	parsed, gate, err := parseSupervisorRequest(bytes.NewReader(encoded))
	if err != nil || gate != "" || parsed.Contract.RoleName != input.Contract.RoleName {
		t.Fatalf("gate=%q err=%v", gate, err)
	}
	duplicate := bytes.Replace(encoded, []byte(`"changeAuthorized":true`), []byte(`"changeAuthorized":true,"changeAuthorized":true`), 1)
	if _, gate, _ := parseSupervisorRequest(bytes.NewReader(duplicate)); gate != "duplicate-field" {
		t.Fatalf("duplicate gate=%q", gate)
	}
	input.SchemaVersion = "unsupported"
	input.RootCredentialBase64 = base64.StdEncoding.EncodeToString([]byte("root-material-canary"))
	encoded, _ = json.Marshal(input)
	report, err := Supervise(context.Background(), bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	reportJSON, _ := json.Marshal(report)
	if strings.Contains(string(reportJSON), "root-material-canary") || report.Status != StatusBlockedPreflight {
		t.Fatalf("unsafe report=%s", reportJSON)
	}
}

func TestRandomPolicyNameIsSafeAndCollisionResistant(t *testing.T) {
	first, err := randomPolicyName(strings.NewReader(strings.Repeat("a", 16)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomPolicyName(strings.NewReader(strings.Repeat("b", 16)))
	if err != nil || first == second || !dnsLabel.MatchString(first) || !dnsLabel.MatchString(second) {
		t.Fatalf("first=%q second=%q err=%v", first, second, err)
	}
}

func validSupervisorRequest(t *testing.T) SupervisorRequest {
	t.Helper()
	request := validRequest(t)
	return SupervisorRequest{
		SchemaVersion: SupervisorSchemaVersion, Contract: request.Contract, OpenBao: request.OpenBao, Kubernetes: request.Kubernetes,
		Lease: request.Lease, ExecutorIdentity: request.ExecutorIdentity, RootCredentialBase64: base64.StdEncoding.EncodeToString([]byte("root-bearer")),
		Seed: request.Seed, NegativeIdentities: request.NegativeIdentities, ChangeAuthorized: true,
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
