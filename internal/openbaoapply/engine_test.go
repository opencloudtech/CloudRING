// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package openbaoapply

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/openbaoauth"
	"github.com/opencloudtech/CloudRING/pkg/openbaobootstrap"
)

func TestExecuteAppliesCompleteDedicatedIdentitySlice(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	report := Execute(context.Background(), request, kubernetes, openBao)
	if report.Status != StatusApplied || !report.MutationPerformed || report.RollbackAttempted || report.FailedGate != "" {
		t.Fatalf("Execute() report=%+v", report)
	}
	if !openBao.mount || !openBao.config || !openBao.policy || !openBao.role || !openBao.seed || !openBao.managementRevoked || kubernetes.lease.HolderIdentity != "" {
		t.Fatalf("post-state mount=%v config=%v policy=%v role=%v seed=%v managementRevoked=%v leaseHolder=%q", openBao.mount, openBao.config, openBao.policy, openBao.role, openBao.seed, openBao.managementRevoked, kubernetes.lease.HolderIdentity)
	}
	encoded, _ := json.Marshal(report)
	if strings.Contains(string(encoded), "consumer-example") || strings.Contains(string(encoded), "secret-value") || report.InputMaterialEchoed {
		t.Fatalf("report reflected request material: %s", encoded)
	}
}

func TestExecuteInitializesAbsentKVV2MountInsideExclusiveLease(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	openBao.kvMount = false
	report := Execute(context.Background(), request, kubernetes, openBao)
	path := "sys/mounts/" + request.Contract.KVV2Mount
	if report.Status != StatusApplied || !report.MutationPerformed || !openBao.kvMount || openBao.writeCounts[path] != 1 || kubernetes.lease.HolderIdentity != "" {
		t.Fatalf("Execute() report=%+v kvMount=%v writes=%d holder=%q", report, openBao.kvMount, openBao.writeCounts[path], kubernetes.lease.HolderIdentity)
	}
	if !slices.Contains(report.CompletedGates, "kv-v2-mount-ready") {
		t.Fatalf("KV-v2 completion gate missing: %+v", report.CompletedGates)
	}
}

func TestExecuteRetainsAmbiguouslyCreatedKVV2MountAndLease(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	openBao.kvMount = false
	openBao.commitThenFailPath = "sys/mounts/" + request.Contract.KVV2Mount
	report := Execute(context.Background(), request, kubernetes, openBao)
	if report.Status != StatusPartialManualInterventionRequired || !report.MutationPerformed || report.FailedGate != "kv-v2-mount-create-ambiguous" || !openBao.kvMount || kubernetes.lease.HolderIdentity == "" {
		t.Fatalf("Execute() report=%+v kvMount=%v holder=%q", report, openBao.kvMount, kubernetes.lease.HolderIdentity)
	}
	for _, path := range openBao.deletePaths {
		if path == "sys/mounts/"+request.Contract.KVV2Mount {
			t.Fatal("ambiguous KV-v2 mount was deleted")
		}
	}
}

func TestExecuteRetainsInitializedKVV2MountWhenLaterMutationRollsBack(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	openBao.kvMount = false
	openBao.definitelyRejectPath = "sys/policies/acl/" + request.Contract.PolicyName
	report := Execute(context.Background(), request, kubernetes, openBao)
	if report.Status != StatusPartialManualInterventionRequired || !report.MutationPerformed || !report.RollbackAttempted || report.FailedGate != "policy-create-rejected" {
		t.Fatalf("Execute() report=%+v", report)
	}
	if !openBao.kvMount || openBao.mount || openBao.config || openBao.policy || openBao.role || openBao.seed || kubernetes.lease.HolderIdentity != "" {
		t.Fatalf("unexpected retained state: kvMount=%v mount=%v config=%v policy=%v role=%v seed=%v holder=%q", openBao.kvMount, openBao.mount, openBao.config, openBao.policy, openBao.role, openBao.seed, kubernetes.lease.HolderIdentity)
	}
	for _, path := range openBao.deletePaths {
		if path == "sys/mounts/"+request.Contract.KVV2Mount {
			t.Fatal("durable KV-v2 mount was deleted during workload-specific rollback")
		}
	}
}

func TestExecuteResolvesCommittedSelfRevokesAfterResponseLoss(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	openBao.commitThenFailPath = "auth/token/revoke-self"
	report := Execute(context.Background(), request, kubernetes, openBao)
	if report.Status != StatusApplied || !openBao.workloadRevoked || !openBao.managementRevoked || kubernetes.lease.HolderIdentity != "" {
		t.Fatalf("Execute() report=%+v workloadRevoked=%v managementRevoked=%v leaseHolder=%q", report, openBao.workloadRevoked, openBao.managementRevoked, kubernetes.lease.HolderIdentity)
	}
}

func TestExecuteRetainsProductionSeedAndLeaseWhenLiveProofFails(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	openBao.failAllowedRead = true
	report := Execute(context.Background(), request, kubernetes, openBao)
	if report.Status != StatusPartialManualInterventionRequired || !report.MutationPerformed || report.RollbackAttempted || report.FailedGate != "allowed-data-read" {
		t.Fatalf("Execute() report=%+v", report)
	}
	if !openBao.mount || !openBao.config || !openBao.policy || !openBao.role || !openBao.seed || !openBao.managementRevoked || kubernetes.lease.HolderIdentity == "" || len(openBao.deletePaths) != 0 {
		t.Fatalf("safe retained post-state mount=%v config=%v policy=%v role=%v seed=%v managementRevoked=%v leaseHolder=%q deletes=%v", openBao.mount, openBao.config, openBao.policy, openBao.role, openBao.seed, openBao.managementRevoked, kubernetes.lease.HolderIdentity, openBao.deletePaths)
	}
}

func TestExecuteTreatsAmbiguousPositiveLoginAsManualIntervention(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	openBao.failPositiveLogin = true
	report := Execute(context.Background(), request, kubernetes, openBao)
	if report.Status != StatusPartialManualInterventionRequired || report.FailedGate != "positive-login" || kubernetes.lease.HolderIdentity == "" {
		t.Fatalf("Execute() report=%+v leaseHolder=%q", report, kubernetes.lease.HolderIdentity)
	}
}

func TestExecuteNeverDeletesProductionSeedDuringFailureCleanup(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	openBao.failPositiveLogin = true
	openBao.driftSeedDuringRollback = true
	report := Execute(context.Background(), request, kubernetes, openBao)
	if report.Status != StatusPartialManualInterventionRequired || report.RollbackAttempted || kubernetes.lease.HolderIdentity == "" || len(openBao.deletePaths) != 0 || !openBao.seed {
		t.Fatalf("Execute() report=%+v leaseHolder=%q", report, kubernetes.lease.HolderIdentity)
	}
}

func TestExecuteRejectsRootTokenAndReleasesLeaseBeforeMutation(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	openBao.rootManagementToken = true
	report := Execute(context.Background(), request, kubernetes, openBao)
	if report.Status != StatusPartialManualInterventionRequired || report.MutationPerformed || report.FailedGate != "management-token-profile" || kubernetes.lease.HolderIdentity == "" {
		t.Fatalf("Execute() report=%+v leaseHolder=%q", report, kubernetes.lease.HolderIdentity)
	}
	if openBao.managementRevoked {
		t.Fatal("executor attempted to revoke a root token")
	}
}

func TestExecuteRejectsUnwrappedAccessorMismatch(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	openBao.managementAccessorOverride = "different-child-accessor"
	report := Execute(context.Background(), request, kubernetes, openBao)
	if report.Status != StatusBlockedPreflight || report.MutationPerformed || report.FailedGate != "management-token-profile" || !openBao.managementRevoked || kubernetes.lease.HolderIdentity != "" {
		t.Fatalf("report=%+v revoked=%v holder=%q", report, openBao.managementRevoked, kubernetes.lease.HolderIdentity)
	}
}

func TestExecuteBlocksExistingPartialMountWithoutMutation(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	openBao.mount = true
	report := Execute(context.Background(), request, kubernetes, openBao)
	if report.Status != StatusBlockedPreflight || report.MutationPerformed || report.FailedGate != "auth-mount-lifecycle" || kubernetes.lease.HolderIdentity != "" {
		t.Fatalf("Execute() report=%+v leaseHolder=%q", report, kubernetes.lease.HolderIdentity)
	}
}

func TestExecuteRejectsOverprivilegedKubernetesToken(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	kubernetes.allowAll = true
	report := Execute(context.Background(), request, kubernetes, newFakeOpenBao(request))
	if report.Status != StatusBlockedPreflight || report.FailedGate != "kubernetes-executor-boundary" {
		t.Fatalf("Execute() report=%+v", report)
	}
}

func TestExecuteRejectsTruncatedWorkloadTTL(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	openBao.loginTTL = 599
	report := Execute(context.Background(), request, kubernetes, openBao)
	if report.Status != StatusPartialManualInterventionRequired || report.FailedGate != "positive-login" || !openBao.workloadRevoked || kubernetes.lease.HolderIdentity == "" {
		t.Fatalf("Execute() report=%+v workloadRevoked=%v", report, openBao.workloadRevoked)
	}
}

func TestExecuteReportsAmbiguousLeaseMutationForManualInspection(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	kubernetes.updateErrorOn = 1
	openBao := newFakeOpenBao(request)
	report := Execute(context.Background(), request, kubernetes, openBao)
	if report.Status != StatusPartialManualInterventionRequired || report.MutationPerformed || report.FailedGate != "exclusive-lease-acquire-ambiguous" {
		t.Fatalf("Execute() report=%+v", report)
	}
}

func TestExecuteRetainsLeaseAfterCommittedWriteLosesItsResponse(t *testing.T) {
	request := validRequest(t)
	paths := []string{
		"sys/auth/" + request.Contract.AuthMount,
		"auth/" + request.Contract.AuthMount + "/config",
		"sys/policies/acl/" + request.Contract.PolicyName,
		"auth/" + request.Contract.AuthMount + "/role/" + request.Contract.RoleName,
		request.Contract.KVV2Mount + "/data/" + fullSeedPath(request),
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			kubernetes := newFakeKubernetes(request)
			openBao := newFakeOpenBao(request)
			openBao.commitThenFailPath = path
			report := Execute(context.Background(), request, kubernetes, openBao)
			if report.Status != StatusPartialManualInterventionRequired || !report.MutationPerformed || kubernetes.lease.HolderIdentity == "" {
				t.Fatalf("Execute() report=%+v state=%+v", report, openBao)
			}
		})
	}
}

func TestExecuteRetainsLeaseWhenAmbiguousSeedWriteReadbackIsAbsent(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	openBao.failWithoutCommitPath = request.Contract.KVV2Mount + "/data/" + fullSeedPath(request)
	report := Execute(context.Background(), request, kubernetes, openBao)
	if report.Status != StatusPartialManualInterventionRequired || !report.MutationPerformed || kubernetes.lease.HolderIdentity == "" {
		t.Fatalf("Execute() report=%+v state=%+v", report, openBao)
	}
}

func TestExecuteReusesExactStateWithoutTargetWrites(t *testing.T) {
	request := validRequest(t)
	firstKubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	if report := Execute(context.Background(), request, firstKubernetes, openBao); report.Status != StatusApplied {
		t.Fatalf("first Execute()=%+v", report)
	}
	openBao.managementRevoked, openBao.workloadRevoked = false, false
	openBao.writeCounts = map[string]int{}
	secondKubernetes := newFakeKubernetes(request)
	report := Execute(context.Background(), request, secondKubernetes, openBao)
	if report.Status != StatusApplied || report.MutationPerformed {
		t.Fatalf("second Execute()=%+v", report)
	}
	for _, path := range []string{"sys/auth/" + request.Contract.AuthMount, "auth/" + request.Contract.AuthMount + "/config", "sys/policies/acl/" + request.Contract.PolicyName, "auth/" + request.Contract.AuthMount + "/role/" + request.Contract.RoleName, request.Contract.KVV2Mount + "/data/" + fullSeedPath(request)} {
		if openBao.writeCounts[path] != 0 {
			t.Fatalf("idempotent run wrote %s", path)
		}
	}
}

func TestExecuteRevokesUnexpectedNegativeLoginToken(t *testing.T) {
	request := validRequest(t)
	kubernetes := newFakeKubernetes(request)
	openBao := newFakeOpenBao(request)
	openBao.issueUnexpectedNegativeToken = true
	report := Execute(context.Background(), request, kubernetes, openBao)
	if report.Status != StatusPartialManualInterventionRequired || report.FailedGate != "negative-login-denial" || !openBao.unexpectedRevoked || kubernetes.lease.HolderIdentity == "" {
		t.Fatalf("Execute() report=%+v unexpectedRevoked=%v", report, openBao.unexpectedRevoked)
	}
}

type fakeKubernetes struct {
	lease         Lease
	request       Request
	updateCalls   int
	updateErrorOn int
	allowAll      bool
	renewFailed   chan struct{}
}

func newFakeKubernetes(request Request) *fakeKubernetes {
	raw := json.RawMessage(`{"apiVersion":"coordination.k8s.io/v1","kind":"Lease","metadata":{"uid":"lease-uid","resourceVersion":"1"},"spec":{"holderIdentity":""}}`)
	return &fakeKubernetes{request: request, lease: Lease{Name: request.Lease.Name, Namespace: request.Lease.Namespace, UID: "lease-uid", ResourceVersion: "1", Raw: raw}, renewFailed: make(chan struct{})}
}

func (client *fakeKubernetes) GetLease(context.Context, LeaseTarget) (Lease, error) {
	return client.lease, nil
}
func (client *fakeKubernetes) UpdateLease(_ context.Context, _ LeaseTarget, lease Lease) (Lease, error) {
	client.updateCalls++
	if client.updateErrorOn == client.updateCalls {
		select {
		case <-client.renewFailed:
		default:
			close(client.renewFailed)
		}
		return Lease{}, errors.New("ambiguous update")
	}
	current, requested := client.lease.ResourceVersion, lease.ResourceVersion
	if current != requested {
		return Lease{}, errors.New("conflict")
	}
	lease.ResourceVersion = incrementVersion(current)
	client.lease = lease
	return lease, nil
}
func (client *fakeKubernetes) GetServiceAccount(_ context.Context, namespace, serviceAccount string) (ServiceAccountFacts, error) {
	if namespace == client.request.ExecutorIdentity.Namespace && serviceAccount == client.request.ExecutorIdentity.ServiceAccount {
		return ServiceAccountFacts{UID: client.request.ExecutorServiceAccountUID}, nil
	}
	if namespace == client.request.Contract.WorkloadIdentity.Namespace && serviceAccount == client.request.Contract.WorkloadIdentity.ServiceAccount {
		return ServiceAccountFacts{UID: "service-account-uid"}, nil
	}
	return ServiceAccountFacts{UID: namespace + ":" + serviceAccount + ":uid"}, nil
}
func (client *fakeKubernetes) ReviewSelf(context.Context) (SubjectFacts, error) {
	return SubjectFacts{
		Username: "system:serviceaccount:" + client.request.ExecutorIdentity.Namespace + ":" + client.request.ExecutorIdentity.ServiceAccount,
		UID:      client.request.ExecutorServiceAccountUID,
		Groups:   []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:" + client.request.ExecutorIdentity.Namespace},
	}, nil
}
func (client *fakeKubernetes) ReviewAccess(_ context.Context, access ResourceAccess) (bool, error) {
	if client.allowAll {
		return true, nil
	}
	if access.Verb == "create" && ((access.Group == "authentication.k8s.io" && access.Resource == "selfsubjectreviews") || (access.Group == "authorization.k8s.io" && access.Resource == "selfsubjectaccessreviews")) {
		return true, nil
	}
	if access.Group == "coordination.k8s.io" && access.Resource == "leases" && access.Namespace == client.request.Lease.Namespace && access.Name == client.request.Lease.Name && (access.Verb == "get" || access.Verb == "update") {
		return true, nil
	}
	if access.Verb == "get" && access.Group == "" && access.Resource == "serviceaccounts" && access.Namespace == client.request.ExecutorIdentity.Namespace && access.Name == client.request.ExecutorIdentity.ServiceAccount {
		return true, nil
	}
	identities := []WorkloadIdentity{
		{Namespace: client.request.Contract.WorkloadIdentity.Namespace, ServiceAccount: client.request.Contract.WorkloadIdentity.ServiceAccount},
		client.request.NegativeIdentities.WrongServiceAccount,
		client.request.NegativeIdentities.WrongNamespace,
	}
	for _, identity := range identities {
		if access.Namespace == identity.Namespace && access.Name == identity.ServiceAccount && access.Resource == "serviceaccounts" &&
			((access.Verb == "get" && access.Subresource == "") || (access.Verb == "create" && access.Subresource == "token")) {
			return true, nil
		}
	}
	return false, nil
}
func (client *fakeKubernetes) RequestServiceAccountToken(_ context.Context, namespace, serviceAccount, audience string, expiration int64) (ServiceAccountToken, error) {
	if expiration != 600 {
		return ServiceAccountToken{}, errors.New("expiration")
	}
	return ServiceAccountToken{JWT: namespace + ":" + serviceAccount + ":" + audience, ExpirationTimestamp: time.Now().Add(600 * time.Second)}, nil
}

func incrementVersion(value string) string {
	if value == "1" {
		return "2"
	}
	if value == "2" {
		return "3"
	}
	return "4"
}

type fakeOpenBao struct {
	request Request
	plan    openbaoauth.Plan

	kvMount, mount, config, policy, role, seed                                       bool
	managementRevoked, workloadRevoked                                               bool
	failPositiveLogin, failAllowedRead, rootManagementToken, driftSeedDuringRollback bool
	seedReadCount                                                                    int
	loginTTL                                                                         int64
	commitThenFailPath, failWithoutCommitPath, definitelyRejectPath                  string
	writeCounts                                                                      map[string]int
	issueUnexpectedNegativeToken, unexpectedRevoked                                  bool
	blockDeleteUntilLeaseLoss                                                        <-chan struct{}
	deletePaths                                                                      []string
	temporaryPolicy, wrapperAccessorRevoked, childAccessorRevoked                    bool
	failWrappedCreate, failSupervisorCleanup, invalidInitialRoot, rootTargetMutation bool
	managementAccessorOverride                                                       string
	wrappedCreateError                                                               error
	policyDeleteResponseLost                                                         bool
}

const fakeSeedCreatedAt = "2026-07-13T12:00:00.123456789Z"

func newFakeOpenBao(request Request) *fakeOpenBao {
	plan, _ := openbaoauth.Build(request.Contract)
	return &fakeOpenBao{request: request, plan: plan, kvMount: true, loginTTL: 600, writeCounts: map[string]int{}, temporaryPolicy: true}
}

func (client *fakeOpenBao) Health(context.Context) error { return nil }
func (client *fakeOpenBao) Unwrap(_ context.Context, token string) (string, error) {
	if token != "wrapping-token" {
		return "", errors.New("unwrap")
	}
	return "management-token", nil
}
func (client *fakeOpenBao) LookupSelf(_ context.Context, token string) (TokenFacts, error) {
	if token == "root-bearer" {
		if client.invalidInitialRoot {
			return TokenFacts{Policies: []string{"root", "unexpected"}, Path: "auth/token/root", Orphan: true, TokenType: "service"}, nil
		}
		return TokenFacts{Policies: []string{"root"}, Accessor: "root-accessor", Path: "auth/token/root", Orphan: true, TokenType: "service"}, nil
	}
	if token == "management-token" {
		if client.rootManagementToken {
			return TokenFacts{Policies: []string{"root"}, TTL: 0, TokenType: "service", Path: "auth/token/create", Orphan: true}, nil
		}
		accessor := client.request.ManagementAccessor
		if client.managementAccessorOverride != "" {
			accessor = client.managementAccessorOverride
		}
		return TokenFacts{Policies: []string{client.request.ManagementPolicyName}, Accessor: accessor, TTL: 600, ExplicitMaxTTL: 900, TokenType: "service", Path: "auth/token/create", Orphan: true, RenewableKnown: true}, nil
	}
	if token == "workload-token" && !client.workloadRevoked {
		return TokenFacts{Policies: []string{client.request.Contract.PolicyName}, Accessor: "workload-accessor", TTL: 600, TokenType: "service", RenewableKnown: true}, nil
	}
	if token == "unexpected-token" && !client.unexpectedRevoked {
		return TokenFacts{Policies: []string{client.request.Contract.PolicyName}, Accessor: "unexpected-accessor", TTL: 600, TokenType: "service", RenewableKnown: true}, nil
	}
	return TokenFacts{}, errors.New("denied")
}
func (client *fakeOpenBao) CapabilitiesSelf(_ context.Context, token string, paths []string) (map[string][]string, error) {
	if token == "management-token" {
		return managementPaths(client.request), nil
	}
	if token != "workload-token" || client.workloadRevoked {
		return nil, errors.New("denied")
	}
	result := make(map[string][]string, len(paths))
	for _, path := range paths {
		switch path {
		case "auth/token/lookup-self":
			result[path] = []string{"read"}
		case "auth/token/revoke-self", "sys/capabilities-self":
			result[path] = []string{"update"}
		default:
			if strings.Contains(path, "/data/") && strings.Contains(path, fullSeedPath(client.request)) {
				result[path] = []string{"read"}
			} else {
				result[path] = []string{"deny"}
			}
		}
	}
	return result, nil
}
func (client *fakeOpenBao) Read(_ context.Context, token, path string) (ReadResult, error) {
	c := client.request.Contract
	switch path {
	case "sys/auth/" + c.AuthMount:
		if !client.mount {
			return ReadResult{}, nil
		}
		data := desiredMap(client.plan.AuthMount)
		data["uuid"], data["accessor"] = "mount-uuid", "mount-accessor"
		data["local"], data["seal_wrap"], data["external_entropy_access"], data["options"] = false, false, false, nil
		data["plugin_version"], data["running_plugin_version"], data["running_sha256"], data["deprecation_status"] = "", "v2.5.5+builtin.bao", "", "supported"
		data["config"] = map[string]any{"default_lease_ttl": json.Number("0"), "max_lease_ttl": json.Number("0"), "force_no_cache": false, "token_type": "default-service"}
		return ReadResult{Found: true, Data: data}, nil
	case "auth/" + c.AuthMount + "/config":
		if !client.config {
			return ReadResult{}, nil
		}
		return ReadResult{Found: true, Data: desiredMap(client.plan.AuthConfigReadback)}, nil
	case "sys/mounts/" + c.KVV2Mount:
		if !client.kvMount {
			return ReadResult{}, nil
		}
		return ReadResult{Found: true, Data: map[string]any{
			"type": "kv", "description": "", "accessor": "kv-accessor", "uuid": "kv-uuid", "local": false, "seal_wrap": false, "external_entropy_access": false,
			"options": map[string]any{"version": "2"}, "plugin_version": "", "running_plugin_version": "v2.5.5+builtin.bao", "running_sha256": "", "deprecation_status": "supported",
			"config": map[string]any{"default_lease_ttl": json.Number("0"), "max_lease_ttl": json.Number("0"), "force_no_cache": false},
		}}, nil
	case "sys/policies/acl/" + c.PolicyName:
		if !client.policy {
			return ReadResult{}, nil
		}
		return ReadResult{Found: true, Data: map[string]any{"name": c.PolicyName, "policy": client.plan.ACLPolicy.Policy, "cas_required": true, "version": json.Number("1"), "modified": fakeSeedCreatedAt}}, nil
	case "sys/policies/acl/" + client.request.ManagementPolicyName:
		if !client.temporaryPolicy {
			return ReadResult{}, nil
		}
		delegation, _ := openbaobootstrap.BuildManagementDelegation(c, client.request.ManagementPolicyName, client.request.Seed.RelativePath)
		return ReadResult{Found: true, Data: map[string]any{"name": client.request.ManagementPolicyName, "policy": delegation.Body, "cas_required": false, "version": json.Number("1"), "modified": fakeSeedCreatedAt}}, nil
	case "auth/" + c.AuthMount + "/role/" + c.RoleName:
		if !client.role {
			return ReadResult{}, nil
		}
		data := desiredMap(client.plan.Role)
		data["token_ttl"], data["token_max_ttl"], data["token_explicit_max_ttl"] = json.Number("600"), json.Number("1800"), json.Number("1800")
		return ReadResult{Found: true, Data: data}, nil
	case c.KVV2Mount + "/metadata/" + fullSeedPath(client.request):
		if !client.seed {
			return ReadResult{}, nil
		}
		return ReadResult{Found: true, Data: map[string]any{
			"versions":        map[string]any{"1": map[string]any{"created_time": fakeSeedCreatedAt, "deletion_time": "", "destroyed": false}},
			"current_version": json.Number("1"), "current_metadata_version": json.Number("0"), "oldest_version": json.Number("0"),
			"created_time": fakeSeedCreatedAt, "updated_time": fakeSeedCreatedAt, "max_versions": json.Number("0"),
			"cas_required": false, "metadata_cas_required": false, "delete_version_after": "0s", "custom_metadata": nil,
		}}, nil
	case c.KVV2Mount + "/data/" + fullSeedPath(client.request):
		if token == "workload-token" && client.failAllowedRead {
			return ReadResult{}, errors.New("read failure")
		}
		if !client.seed {
			return ReadResult{}, nil
		}
		client.seedReadCount++
		data, _ := decodedSeed(client.request.Seed)
		if client.driftSeedDuringRollback && client.failPositiveLogin && client.seedReadCount >= 2 {
			data["cloud"] = "drift"
		}
		return ReadResult{Found: true, Data: map[string]any{"data": data, "metadata": map[string]any{"version": json.Number("1"), "created_time": fakeSeedCreatedAt, "destroyed": false, "deletion_time": "", "custom_metadata": nil}}}, nil
	default:
		if token == "workload-token" {
			return ReadResult{}, errors.New("denied")
		}
		return ReadResult{}, nil
	}
}
func (client *fakeOpenBao) List(_ context.Context, _ string, path string) (ReadResult, error) {
	if path != "auth/"+client.request.Contract.AuthMount+"/role" || !client.mount {
		return ReadResult{}, nil
	}
	keys := []any{}
	if client.role {
		keys = append(keys, client.request.Contract.RoleName)
	}
	return ReadResult{Found: true, Data: map[string]any{"keys": keys}}, nil
}
func (client *fakeOpenBao) Write(_ context.Context, token, path string, body any) (ReadResult, error) {
	client.writeCounts[path]++
	if client.definitelyRejectPath == path {
		return ReadResult{}, errDefinitelyRejected
	}
	if client.failWithoutCommitPath == path {
		return ReadResult{}, errMutationAmbiguous
	}
	c := client.request.Contract
	result := ReadResult{Found: true}
	switch path {
	case "sys/policies/acl/" + client.request.ManagementPolicyName:
		if token == "root-bearer" {
			client.temporaryPolicy = true
			break
		}
		client.rootTargetMutation = true
	case "sys/auth/" + c.AuthMount:
		client.mount = true
	case "sys/mounts/" + c.KVV2Mount:
		if !equalJSON(body, desiredMap(client.plan.KVV2Mount)) {
			return ReadResult{}, errors.New("unexpected KV-v2 mount body")
		}
		client.kvMount = true
	case "auth/" + c.AuthMount + "/config":
		client.config = true
	case "sys/policies/acl/" + c.PolicyName:
		client.policy = true
	case "auth/" + c.AuthMount + "/role/" + c.RoleName:
		client.role = true
	case c.KVV2Mount + "/data/" + fullSeedPath(client.request):
		client.seed = true
		result.Data = map[string]any{"version": json.Number("1"), "created_time": fakeSeedCreatedAt, "deletion_time": "", "destroyed": false, "custom_metadata": nil}
	case "auth/" + c.AuthMount + "/login":
		if client.failPositiveLogin {
			return ReadResult{}, errors.New("login")
		}
		requestBody := body.(map[string]any)
		jwt, _ := requestBody["jwt"].(string)
		want := c.WorkloadIdentity.Namespace + ":" + c.WorkloadIdentity.ServiceAccount + ":" + c.Audience
		if jwt != want {
			if client.issueUnexpectedNegativeToken {
				return ReadResult{Found: true, Auth: map[string]any{"client_token": "unexpected-token"}}, nil
			}
			return ReadResult{}, errForbidden
		}
		return ReadResult{Found: true, Auth: map[string]any{
			"client_token": "workload-token", "accessor": "workload-accessor", "entity_id": "workload-entity", "policies": []any{c.PolicyName}, "token_policies": []any{c.PolicyName},
			"lease_duration": json.Number(strconv.FormatInt(client.loginTTL, 10)), "mfa_requirement": nil, "num_uses": json.Number("0"), "orphan": true, "renewable": true, "token_type": "service",
			"metadata": map[string]any{"role": c.RoleName, "service_account_name": c.WorkloadIdentity.ServiceAccount, "service_account_namespace": c.WorkloadIdentity.Namespace, "service_account_secret_name": "", "service_account_uid": "service-account-uid"},
		}}, nil
	case "auth/token/revoke-self":
		if token == "management-token" {
			client.managementRevoked = true
		} else if token == "workload-token" {
			client.workloadRevoked = true
		} else if token == "unexpected-token" {
			client.unexpectedRevoked = true
		}
	default:
		return ReadResult{}, errors.New("unexpected write")
	}
	if client.commitThenFailPath == path {
		return ReadResult{}, errMutationAmbiguous
	}
	return result, nil
}
func (client *fakeOpenBao) Delete(ctx context.Context, _ string, path string) error {
	client.deletePaths = append(client.deletePaths, path)
	if client.blockDeleteUntilLeaseLoss != nil && len(client.deletePaths) == 1 {
		<-client.blockDeleteUntilLeaseLoss
		<-ctx.Done()
		return ctx.Err()
	}
	c := client.request.Contract
	switch path {
	case "sys/policies/acl/" + client.request.ManagementPolicyName:
		client.temporaryPolicy = false
		if client.policyDeleteResponseLost {
			return errMutationAmbiguous
		}
	case c.KVV2Mount + "/metadata/" + fullSeedPath(client.request):
		client.seed = false
	case "auth/" + c.AuthMount + "/role/" + c.RoleName:
		client.role = false
	case "sys/policies/acl/" + c.PolicyName:
		client.policy = false
	case "sys/auth/" + c.AuthMount:
		client.mount, client.config = false, false
	default:
		return errors.New("unexpected delete")
	}
	return nil
}

func (client *fakeOpenBao) CreateWrappedManagementToken(context.Context, string, string, string) (WrappedToken, error) {
	if client.wrappedCreateError != nil {
		return WrappedToken{}, client.wrappedCreateError
	}
	if client.failWrappedCreate {
		return WrappedToken{}, errMutationAmbiguous
	}
	return WrappedToken{Value: "wrapping-token", Accessor: "wrapper-accessor", WrappedAccessor: "child-accessor", CreationPath: "auth/token/create"}, nil
}

func (client *fakeOpenBao) RevokeAccessorAndProve(_ context.Context, _ string, accessor string) bool {
	if client.failSupervisorCleanup {
		return false
	}
	switch accessor {
	case "wrapper-accessor":
		client.wrapperAccessorRevoked = true
	case "child-accessor":
		client.childAccessorRevoked = true
	default:
		return false
	}
	return true
}
func (client *fakeOpenBao) ExpectForbidden(_ context.Context, method, token, path string, body any) error {
	if path == "auth/token/lookup-self" {
		if token == "workload-token" && client.workloadRevoked {
			return nil
		}
		if token == "management-token" && client.managementRevoked {
			return nil
		}
		if token == "unexpected-token" && client.unexpectedRevoked {
			return nil
		}
		return errors.New("not denied")
	}
	if strings.HasSuffix(path, "/login") {
		jwt := body.(map[string]any)["jwt"].(string)
		want := client.request.Contract.WorkloadIdentity.Namespace + ":" + client.request.Contract.WorkloadIdentity.ServiceAccount + ":" + client.request.Contract.Audience
		if jwt != want {
			return nil
		}
		return errors.New("not denied")
	}
	if token == "workload-token" && (method == "GET" || method == "POST") {
		return nil
	}
	return errors.New("not denied")
}

func (client *fakeOpenBao) ApplyClient() OpenBaoClient { return client }

func (client *fakeOpenBao) LookupInitialRoot(ctx context.Context, rootBearer string) (TokenFacts, error) {
	return client.LookupSelf(ctx, rootBearer)
}

func (client *fakeOpenBao) ReadTemporaryPolicy(ctx context.Context, rootBearer, policyName string) (ReadResult, error) {
	return client.Read(ctx, rootBearer, "sys/policies/acl/"+policyName)
}

func (client *fakeOpenBao) CreateTemporaryPolicy(ctx context.Context, rootBearer, policyName, body string) error {
	_, err := client.Write(ctx, rootBearer, "sys/policies/acl/"+policyName, map[string]any{"policy": body, "cas": -1, "cas_required": false})
	return err
}

func (client *fakeOpenBao) DeleteTemporaryPolicy(ctx context.Context, rootBearer, policyName string) error {
	return client.Delete(ctx, rootBearer, "sys/policies/acl/"+policyName)
}
