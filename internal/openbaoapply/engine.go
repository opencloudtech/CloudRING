// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package openbaoapply

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/openbaoauth"
	"github.com/opencloudtech/CloudRING/pkg/openbaobootstrap"
)

var reportNonClaims = []string{
	"ESO SecretStore readiness is not claimed",
	"ExternalSecret synchronization is not claimed",
	"credential rotation and disaster recovery are not claimed",
	"production readiness is not claimed",
	"the request binding is not a standalone authorization receipt",
}

type mutationState struct {
	kvMountCreated  bool
	kvMountUUID     string
	kvMountAccessor string
	mountCreated    bool
	mountUUID       string
	mountAccessor   string
	policyCreated   bool
	policyVersion   int64
	policyModified  string
	roleCreated     bool
	seedCreated     bool
	seedCreatedAt   string
	mutated         bool
}

type preState struct {
	mount    ReadResult
	config   ReadResult
	roles    ReadResult
	kvMount  ReadResult
	policy   ReadResult
	role     ReadResult
	metadata ReadResult
	seed     ReadResult
}

// Apply parses one request, creates hardened clients, and executes the complete
// dedicated workload-identity plus one-secret vertical slice.
func Apply(ctx context.Context, reader interface{ Read([]byte) (int, error) }) (Report, error) {
	request, failedGate, err := Parse(reader)
	if err != nil {
		return Report{}, err
	}
	if failedGate != "" {
		return fixedReport(StatusBlockedPreflight, false, false, failedGate, nil), nil
	}
	kubernetes, err := NewKubernetesClient(request.Kubernetes)
	if err != nil {
		return fixedReport(StatusBlockedPreflight, false, false, "secure-client", nil), nil
	}
	openBao, err := NewOpenBaoClient(request.OpenBao)
	if err != nil {
		return fixedReport(StatusBlockedPreflight, false, false, "secure-client", nil), nil
	}
	return Execute(ctx, request, kubernetes, openBao), nil
}

// Execute is exported inside the internal package boundary for deterministic
// state-machine tests with exact fake clients.
func Execute(ctx context.Context, request Request, kubernetes KubernetesClient, openBao OpenBaoClient) Report {
	completed := make([]string, 0, 16)
	if err := openBao.Health(ctx); err != nil {
		return fixedReport(StatusBlockedPreflight, false, false, "openbao-health", completed)
	}
	completed = append(completed, "openbao-active-unsealed")
	positiveServiceAccountUID, kubernetesBoundaryReady := verifyKubernetesBoundary(ctx, kubernetes, request)
	if !kubernetesBoundaryReady {
		return fixedReport(StatusBlockedPreflight, false, false, "kubernetes-executor-boundary", completed)
	}
	completed = append(completed, "kubernetes-executor-boundary")

	guard, leaseMutationAttempted, err := acquireLease(ctx, kubernetes, request.Lease)
	if err != nil {
		if leaseMutationAttempted {
			return fixedReport(StatusPartialManualInterventionRequired, false, false, "exclusive-lease-acquire-ambiguous", completed)
		}
		return fixedReport(StatusBlockedPreflight, false, false, "exclusive-lease", completed)
	}
	completed = append(completed, "exclusive-lease-acquired")
	releaseBlocked := func(failedGate string) Report {
		if err := guard.release(context.WithoutCancel(ctx)); err != nil {
			return fixedReport(StatusPartialManualInterventionRequired, false, false, "lease-release", completed)
		}
		return fixedReport(StatusBlockedPreflight, false, false, failedGate, completed)
	}

	wrappingBytes, _ := base64.StdEncoding.Strict().DecodeString(request.WrappingTokenBase64)
	managementToken, err := openBao.Unwrap(guard.Context(), string(wrappingBytes))
	zeroBytes(wrappingBytes)
	if err != nil {
		if errors.Is(err, errDefinitelyRejected) || errors.Is(err, errForbidden) {
			return releaseBlocked("management-token-unwrap")
		}
		guard.abandon()
		return fixedReport(StatusPartialManualInterventionRequired, false, false, "management-token-unwrap-ambiguous", completed)
	}
	completed = append(completed, "management-token-unwrapped")

	mutations := mutationState{}
	revokeManagement := func(callCtx context.Context) bool {
		return revokeAndProve(callCtx, openBao, managementToken)
	}
	blockAfterManagement := func(failedGate string) Report {
		if mutations.kvMountCreated && !kvV2MountStillOwned(guard.CleanupContext(), openBao, managementToken, request, mutations) {
			guard.abandon()
			return fixedReport(StatusPartialManualInterventionRequired, true, false, "kv-v2-mount-ownership", completed)
		}
		if !revokeManagement(guard.CleanupContext()) {
			guard.abandon()
			return fixedReport(StatusPartialManualInterventionRequired, false, false, "management-token-revoke", completed)
		}
		if mutations.kvMountCreated {
			if err := guard.release(context.WithoutCancel(ctx)); err != nil {
				return fixedReport(StatusPartialManualInterventionRequired, true, false, "lease-release", completed)
			}
			return fixedReport(StatusPartialManualInterventionRequired, true, false, failedGate, completed)
		}
		return releaseBlocked(failedGate)
	}
	facts, err := openBao.LookupSelf(guard.Context(), managementToken)
	if err != nil {
		guard.abandon()
		return fixedReport(StatusPartialManualInterventionRequired, false, false, "management-token-profile-unknown", completed)
	}
	if !validManagementToken(facts, request.ManagementPolicyName) || facts.Accessor != request.ManagementAccessor {
		if provenNonRoot(facts) {
			return blockAfterManagement("management-token-profile")
		}
		guard.abandon()
		return fixedReport(StatusPartialManualInterventionRequired, false, false, "management-token-profile", completed)
	}
	delegation, err := openbaobootstrap.BuildManagementDelegation(request.Contract, request.ManagementPolicyName, request.Seed.RelativePath)
	if err != nil {
		return blockAfterManagement("management-policy-contract")
	}
	paths := delegation.Paths
	capabilities, err := openBao.CapabilitiesSelf(guard.Context(), managementToken, orderedKeys(paths))
	if err != nil || !exactManagementCapabilities(capabilities, paths) {
		return blockAfterManagement("management-token-capabilities")
	}
	managementPolicy, err := openBao.Read(guard.Context(), managementToken, "sys/policies/acl/"+request.ManagementPolicyName)
	if err != nil || !exactManagementPolicy(managementPolicy, request.ManagementPolicyName, delegation.Body) {
		return blockAfterManagement("management-policy-readback")
	}
	completed = append(completed, "management-token-least-privilege")

	plan, problems := openbaoauth.Build(request.Contract)
	if len(problems) != 0 {
		return blockAfterManagement("planner-contract")
	}
	state, gate := capturePreState(guard.Context(), openBao, managementToken, request, plan)
	if gate != "" {
		return blockAfterManagement(gate)
	}
	completed = append(completed, "complete-prestate-captured")
	if gate = validatePreState(request, plan, state); gate != "" {
		return blockAfterManagement(gate)
	}
	completed = append(completed, "prestate-allows-mutation")

	holdForManualInspection := func(failedGate string, mutationPossible bool) Report {
		if mutationPossible {
			mutations.mutated = true
		}
		if guard.healthy() {
			_ = revokeManagement(guard.CleanupContext())
		}
		guard.abandon()
		return fixedReport(StatusPartialManualInterventionRequired, mutations.mutated, false, failedGate, completed)
	}
	failAfterMutationWithCleanup := func(failedGate string, cleanupUncertain bool) Report {
		if !mutations.mutated {
			if cleanupUncertain {
				return holdForManualInspection(failedGate, false)
			}
			if !revokeManagement(guard.CleanupContext()) {
				guard.abandon()
				return fixedReport(StatusPartialManualInterventionRequired, false, false, "management-token-revoke", completed)
			}
			if err := guard.release(context.WithoutCancel(ctx)); err != nil {
				return fixedReport(StatusPartialManualInterventionRequired, false, false, "lease-release", completed)
			}
			return fixedReport(StatusBlockedPreflight, false, false, failedGate, completed)
		}
		// KV-v2 has no compare-and-delete operation for metadata. Once the
		// fixed production seed may exist, automatic deletion could destroy a
		// concurrent version. Retain the Lease and require an owned manual
		// recovery instead of making a false rollback claim.
		if mutations.seedCreated {
			return holdForManualInspection(failedGate, true)
		}
		if !guard.healthy() {
			guard.abandon()
			return fixedReport(StatusPartialManualInterventionRequired, mutations.mutated, false, "exclusive-lease-lost", completed)
		}
		rolledBack := rollback(guard.CleanupContext(), openBao, managementToken, request, plan, mutations)
		managementRevoked := revokeManagement(guard.CleanupContext())
		if !rolledBack || !managementRevoked {
			guard.abandon()
			return fixedReport(StatusPartialManualInterventionRequired, mutations.mutated, true, failedGate, completed)
		}
		if cleanupUncertain {
			guard.abandon()
			return fixedReport(StatusPartialManualInterventionRequired, mutations.mutated, true, failedGate, completed)
		}
		if err := guard.release(context.WithoutCancel(ctx)); err != nil {
			return fixedReport(StatusPartialManualInterventionRequired, mutations.mutated, true, "lease-release", completed)
		}
		if mutations.kvMountCreated {
			return fixedReport(StatusPartialManualInterventionRequired, true, true, failedGate, completed)
		}
		return fixedReport(StatusRolledBack, mutations.mutated, true, failedGate, completed)
	}
	failAfterMutation := func(failedGate string) Report {
		return failAfterMutationWithCleanup(failedGate, false)
	}

	if !state.kvMount.Found {
		if !guard.healthy() {
			guard.abandon()
			return fixedReport(StatusPartialManualInterventionRequired, false, false, "exclusive-lease-lost", completed)
		}
		if !completePreStateUnchanged(guard.Context(), openBao, managementToken, request, plan, state) {
			return blockAfterManagement("prewrite-prestate-changed")
		}
		mountPath := "sys/mounts/" + request.Contract.KVV2Mount
		_, writeErr := openBao.Write(guard.Context(), managementToken, mountPath, desiredMap(plan.KVV2Mount))
		mount, readErr := openBao.Read(guard.Context(), managementToken, mountPath)
		if readErr != nil {
			return holdForManualInspection("kv-v2-mount-create-ambiguous", true)
		}
		if !mount.Found {
			if definitelyRejected(writeErr) {
				return blockAfterManagement("kv-v2-mount-create-rejected")
			}
			return holdForManualInspection("kv-v2-mount-create-ambiguous", true)
		}
		if writeErr != nil {
			return holdForManualInspection("kv-v2-mount-create-ambiguous", true)
		}
		if !exactKVV2Mount(mount) {
			return holdForManualInspection("kv-v2-mount-create-drifted", true)
		}
		mutations.kvMountCreated, mutations.kvMountUUID, mutations.kvMountAccessor = true, textValue(mount.Data, "uuid"), textValue(mount.Data, "accessor")
		mutations.mutated = true
	}
	completed = append(completed, "kv-v2-mount-ready")

	if !state.mount.Found {
		if !guard.healthy() {
			guard.abandon()
			return fixedReport(StatusPartialManualInterventionRequired, false, false, "exclusive-lease-lost", completed)
		}
		if !mountPrestateStillAbsent(guard.Context(), openBao, managementToken, request) {
			return blockAfterManagement("prewrite-prestate-changed")
		}
		mountPath := "sys/auth/" + request.Contract.AuthMount
		_, writeErr := openBao.Write(guard.Context(), managementToken, mountPath, plan.AuthMount)
		mount, readErr := openBao.Read(guard.Context(), managementToken, mountPath)
		if readErr != nil {
			return holdForManualInspection("auth-mount-create-ambiguous", true)
		}
		if !mount.Found {
			if definitelyRejected(writeErr) {
				return blockAfterManagement("auth-mount-create-rejected")
			}
			return holdForManualInspection("auth-mount-create-ambiguous", true)
		}
		if writeErr != nil {
			return holdForManualInspection("auth-mount-create-ambiguous", true)
		}
		if !exactMount(mount, plan.AuthMount) {
			return holdForManualInspection("auth-mount-create-drifted", true)
		}
		mutations.mutated = true
		mountUUID, mountAccessor := textValue(mount.Data, "uuid"), textValue(mount.Data, "accessor")
		if mountUUID == "" || mountAccessor == "" {
			return holdForManualInspection("auth-mount-ownership-readback", true)
		}
		mutations.mountCreated, mutations.mountUUID, mutations.mountAccessor = true, mountUUID, mountAccessor
		configBeforeWrite, configErr := openBao.Read(guard.Context(), managementToken, "auth/"+request.Contract.AuthMount+"/config")
		rolesBeforeWrite, rolesErr := openBao.List(guard.Context(), managementToken, "auth/"+request.Contract.AuthMount+"/role")
		if configErr != nil || rolesErr != nil || configBeforeWrite.Found || !noRoles(rolesBeforeWrite) {
			return failAfterMutation("auth-config-prewrite-readback")
		}
		configPath := "auth/" + request.Contract.AuthMount + "/config"
		_, configWriteErr := openBao.Write(guard.Context(), managementToken, configPath, plan.AuthConfig)
		config, configReadErr := openBao.Read(guard.Context(), managementToken, configPath)
		if configReadErr != nil {
			return holdForManualInspection("auth-config-create-ambiguous", true)
		}
		if !config.Found {
			if definitelyRejected(configWriteErr) {
				return failAfterMutation("auth-config-create-rejected")
			}
			return holdForManualInspection("auth-config-create-ambiguous", true)
		}
		if configWriteErr != nil {
			return holdForManualInspection("auth-config-create-ambiguous", true)
		}
		if !exactConfig(config, plan.AuthConfigReadback) {
			return holdForManualInspection("auth-config-create-drifted", true)
		}
	}
	completed = append(completed, "dedicated-auth-mount-ready")

	if !state.policy.Found {
		policyPath := "sys/policies/acl/" + request.Contract.PolicyName
		if !guard.healthy() || !authMountStillOwned(guard.Context(), openBao, managementToken, request, plan, mutations) || !unchangedBeforeWrite(guard.Context(), openBao, managementToken, policyPath, state.policy) {
			return failAfterMutation("policy-prewrite-readback")
		}
		_, policyWriteErr := openBao.Write(guard.Context(), managementToken, policyPath, plan.ACLPolicy)
		policy, policyReadErr := openBao.Read(guard.Context(), managementToken, policyPath)
		if policyReadErr != nil {
			return holdForManualInspection("policy-create-ambiguous", true)
		}
		if !policy.Found {
			if definitelyRejected(policyWriteErr) {
				return failAfterMutation("policy-create-rejected")
			}
			return holdForManualInspection("policy-create-ambiguous", true)
		}
		if policyWriteErr != nil {
			return holdForManualInspection("policy-create-ambiguous", true)
		}
		if !exactPolicy(policy, request.Contract.PolicyName, plan.ACLPolicy) {
			return holdForManualInspection("policy-create-drifted", true)
		}
		version, ok := integer(policy.Data, "version")
		if !ok || version != 1 {
			return holdForManualInspection("policy-version-readback", true)
		}
		mutations.policyCreated, mutations.mutated = true, true
		mutations.policyVersion, mutations.policyModified = version, textValue(policy.Data, "modified")
	}
	completed = append(completed, "acl-policy-ready")

	if !state.role.Found {
		rolePath := "auth/" + request.Contract.AuthMount + "/role/" + request.Contract.RoleName
		if !guard.healthy() || !authMountStillOwned(guard.Context(), openBao, managementToken, request, plan, mutations) || !unchangedBeforeWrite(guard.Context(), openBao, managementToken, rolePath, state.role) {
			return failAfterMutation("role-prewrite-readback")
		}
		_, roleWriteErr := openBao.Write(guard.Context(), managementToken, rolePath, plan.Role)
		role, roleReadErr := openBao.Read(guard.Context(), managementToken, rolePath)
		if roleReadErr != nil {
			return holdForManualInspection("role-create-ambiguous", true)
		}
		if !role.Found {
			if definitelyRejected(roleWriteErr) {
				return failAfterMutation("role-create-rejected")
			}
			return holdForManualInspection("role-create-ambiguous", true)
		}
		if roleWriteErr != nil {
			return holdForManualInspection("role-create-ambiguous", true)
		}
		if !exactRole(role, plan.Role) {
			return holdForManualInspection("role-create-drifted", true)
		}
		mutations.roleCreated, mutations.mutated = true, true
	}
	completed = append(completed, "workload-role-ready")

	seedData, _ := decodedSeed(request.Seed)
	seedPath := fullSeedPath(request)
	if !state.metadata.Found {
		if !guard.healthy() || !authMountStillOwned(guard.Context(), openBao, managementToken, request, plan, mutations) || !unchangedBeforeWrite(guard.Context(), openBao, managementToken, ""+request.Contract.KVV2Mount+"/metadata/"+seedPath, state.metadata) {
			return failAfterMutation("seed-prewrite-readback")
		}
		body := map[string]any{"options": map[string]any{"cas": 0}, "data": seedData}
		seedWrite, seedWriteErr := openBao.Write(guard.Context(), managementToken, request.Contract.KVV2Mount+"/data/"+seedPath, body)
		metadata, metadataErr := openBao.Read(guard.Context(), managementToken, request.Contract.KVV2Mount+"/metadata/"+seedPath)
		if metadataErr != nil {
			return holdForManualInspection("seed-create-ambiguous", true)
		}
		if !metadata.Found {
			if definitelyRejected(seedWriteErr) {
				return failAfterMutation("seed-create-rejected")
			}
			return holdForManualInspection("seed-create-ambiguous", true)
		}
		if seedWriteErr != nil {
			return holdForManualInspection("seed-create-ambiguous", true)
		}
		seed, seedReadErr := openBao.Read(guard.Context(), managementToken, request.Contract.KVV2Mount+"/data/"+seedPath)
		createdAt, seedExact := exactSeed(metadata, seed, seedData)
		if seedReadErr != nil || !seed.Found || !seedExact || !exactSeedWrite(seedWrite, createdAt) {
			return holdForManualInspection("seed-create-drifted", true)
		}
		mutations.seedCreated, mutations.seedCreatedAt, mutations.mutated = true, createdAt, true
	}
	completed = append(completed, "kv-v2-seed-ready")

	if gate, cleanupSafe := verifyWorkloadAuthorization(guard.Context(), kubernetes, openBao, request, positiveServiceAccountUID, seedData); gate != "" {
		return failAfterMutationWithCleanup(gate, !cleanupSafe)
	}
	completed = append(completed, "workload-live-authorization-proven")
	if !revokeManagement(guard.CleanupContext()) {
		guard.abandon()
		return fixedReport(StatusPartialManualInterventionRequired, mutations.mutated, false, "management-token-revoke", completed)
	}
	completed = append(completed, "management-token-revoked")
	if err := guard.release(context.WithoutCancel(ctx)); err != nil {
		return fixedReport(StatusPartialManualInterventionRequired, mutations.mutated, false, "lease-release", completed)
	}
	completed = append(completed, "exclusive-lease-released")
	return fixedReport(StatusApplied, mutations.mutated, false, "", completed)
}

func capturePreState(ctx context.Context, client OpenBaoClient, token string, request Request, plan openbaoauth.Plan) (preState, string) {
	reads := []struct {
		path string
		list bool
		out  *ReadResult
	}{
		{"sys/auth/" + request.Contract.AuthMount, false, nil},
		{"auth/" + request.Contract.AuthMount + "/config", false, nil},
		{"auth/" + request.Contract.AuthMount + "/role", true, nil},
		{"sys/mounts/" + request.Contract.KVV2Mount, false, nil},
		{"sys/policies/acl/" + request.Contract.PolicyName, false, nil},
		{"auth/" + request.Contract.AuthMount + "/role/" + request.Contract.RoleName, false, nil},
		{request.Contract.KVV2Mount + "/metadata/" + fullSeedPath(request), false, nil},
	}
	var state preState
	reads[0].out, reads[1].out, reads[2].out = &state.mount, &state.config, &state.roles
	reads[3].out, reads[4].out, reads[5].out, reads[6].out = &state.kvMount, &state.policy, &state.role, &state.metadata
	for _, read := range reads {
		var result ReadResult
		var err error
		if read.list {
			result, err = client.List(ctx, token, read.path)
		} else {
			result, err = client.Read(ctx, token, read.path)
		}
		if err != nil {
			return preState{}, "complete-prestate"
		}
		*read.out = result
	}
	if state.metadata.Found {
		seed, err := client.Read(ctx, token, request.Contract.KVV2Mount+"/data/"+fullSeedPath(request))
		if err != nil {
			return preState{}, "complete-prestate"
		}
		state.seed = seed
	}
	return state, ""
}

func completePreStateUnchanged(ctx context.Context, client OpenBaoClient, token string, request Request, plan openbaoauth.Plan, prior preState) bool {
	current, gate := capturePreState(ctx, client, token, request, plan)
	if gate != "" {
		return false
	}
	return equalReadResult(current.mount, prior.mount) && equalReadResult(current.config, prior.config) &&
		equalReadResult(current.roles, prior.roles) && equalReadResult(current.kvMount, prior.kvMount) &&
		equalReadResult(current.policy, prior.policy) && equalReadResult(current.role, prior.role) &&
		equalReadResult(current.metadata, prior.metadata) && equalReadResult(current.seed, prior.seed)
}

func equalReadResult(left, right ReadResult) bool {
	return left.Found == right.Found && equalJSON(left.Data, right.Data) && equalJSON(left.Auth, right.Auth)
}

func validatePreState(request Request, plan openbaoauth.Plan, state preState) string {
	if state.kvMount.Found && !exactKVV2Mount(state.kvMount) {
		return "kv-v2-mount-prestate"
	}
	if !state.kvMount.Found && (state.metadata.Found || state.seed.Found) {
		return "kv-v2-mount-prestate"
	}
	seedData, _ := decodedSeed(request.Seed)
	if !state.mount.Found {
		if state.config.Found || state.roles.Found || state.role.Found || state.policy.Found || state.metadata.Found || state.seed.Found {
			return "orphaned-prestate"
		}
		return ""
	}
	if !exactMount(state.mount, plan.AuthMount) || !exactConfig(state.config, plan.AuthConfigReadback) || !noForeignRoles(state.roles, request.Contract.RoleName) {
		return "auth-mount-lifecycle"
	}
	if !state.policy.Found || !exactPolicy(state.policy, request.Contract.PolicyName, plan.ACLPolicy) || !state.role.Found || !exactRole(state.role, plan.Role) {
		return "existing-state-incomplete-or-drifted"
	}
	if !state.metadata.Found || !state.seed.Found {
		return "existing-seed-incomplete-or-drifted"
	}
	if _, exact := exactSeed(state.metadata, state.seed, seedData); !exact {
		return "existing-seed-incomplete-or-drifted"
	}
	return ""
}

func validManagementToken(facts TokenFacts, policy string) bool {
	return facts.TTL > 0 && facts.TTL <= 900 && facts.ExplicitMaxTTL > 0 && facts.ExplicitMaxTTL <= 900 &&
		facts.RenewableKnown && !facts.Renewable && facts.Orphan && facts.TokenType == "service" && facts.Path == "auth/token/create" && facts.Accessor != "" &&
		facts.NumUses == 0 && facts.MetadataEntries == 0 && facts.EntityID == "" && len(facts.IdentityPolicies) == 0 &&
		facts.ExternalNamespacePolicies == 0 && equalStrings(facts.Policies, []string{policy})
}

func verifyKubernetesBoundary(ctx context.Context, client KubernetesClient, request Request) (string, bool) {
	subject, err := client.ReviewSelf(ctx)
	wantUsername := "system:serviceaccount:" + request.ExecutorIdentity.Namespace + ":" + request.ExecutorIdentity.ServiceAccount
	wantGroups := []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:" + request.ExecutorIdentity.Namespace}
	if err != nil || subject.Username != wantUsername || subject.UID == "" || subject.UID != request.ExecutorServiceAccountUID || !equalStrings(subject.Groups, wantGroups) {
		return "", false
	}
	executorFacts, err := client.GetServiceAccount(ctx, request.ExecutorIdentity.Namespace, request.ExecutorIdentity.ServiceAccount)
	if err != nil || executorFacts.UID != request.ExecutorServiceAccountUID {
		return "", false
	}
	identities := []WorkloadIdentity{
		{Namespace: request.Contract.WorkloadIdentity.Namespace, ServiceAccount: request.Contract.WorkloadIdentity.ServiceAccount},
		request.NegativeIdentities.WrongServiceAccount,
		request.NegativeIdentities.WrongNamespace,
	}
	seenUIDs := make(map[string]bool, len(identities))
	positiveUID := ""
	for _, identity := range identities {
		facts, err := client.GetServiceAccount(ctx, identity.Namespace, identity.ServiceAccount)
		if err != nil || facts.UID == "" || seenUIDs[facts.UID] {
			return "", false
		}
		seenUIDs[facts.UID] = true
		if identity.Namespace == request.Contract.WorkloadIdentity.Namespace && identity.ServiceAccount == request.Contract.WorkloadIdentity.ServiceAccount {
			positiveUID = facts.UID
		}
	}
	positive := []ResourceAccess{
		{Verb: "create", Group: "authentication.k8s.io", Resource: "selfsubjectreviews"},
		{Verb: "create", Group: "authorization.k8s.io", Resource: "selfsubjectaccessreviews"},
		{Verb: "get", Group: "coordination.k8s.io", Resource: "leases", Namespace: request.Lease.Namespace, Name: request.Lease.Name},
		{Verb: "update", Group: "coordination.k8s.io", Resource: "leases", Namespace: request.Lease.Namespace, Name: request.Lease.Name},
		{Verb: "get", Resource: "serviceaccounts", Namespace: request.ExecutorIdentity.Namespace, Name: request.ExecutorIdentity.ServiceAccount},
	}
	for _, identity := range identities {
		positive = append(positive,
			ResourceAccess{Verb: "get", Resource: "serviceaccounts", Namespace: identity.Namespace, Name: identity.ServiceAccount},
			ResourceAccess{Verb: "create", Resource: "serviceaccounts", Subresource: "token", Namespace: identity.Namespace, Name: identity.ServiceAccount},
		)
	}
	negative := []ResourceAccess{
		{Verb: "create", Group: "authentication.k8s.io", Resource: "tokenreviews"},
		{Verb: "create", Group: "authorization.k8s.io", Resource: "subjectaccessreviews"},
		{Verb: "create", Group: "coordination.k8s.io", Resource: "leases", Namespace: request.Lease.Namespace, Name: request.Lease.Name},
		{Verb: "patch", Group: "coordination.k8s.io", Resource: "leases", Namespace: request.Lease.Namespace, Name: request.Lease.Name},
		{Verb: "delete", Group: "coordination.k8s.io", Resource: "leases", Namespace: request.Lease.Namespace, Name: request.Lease.Name},
		{Verb: "list", Group: "coordination.k8s.io", Resource: "leases", Namespace: request.Lease.Namespace},
		{Verb: "get", Group: "coordination.k8s.io", Resource: "leases", Namespace: request.Lease.Namespace, Name: distinctProbeLabel(request.Lease.Name)},
		{Verb: "update", Group: "coordination.k8s.io", Resource: "leases", Namespace: request.Lease.Namespace, Name: distinctProbeLabel(request.Lease.Name)},
		{Verb: "create", Resource: "serviceaccounts", Namespace: request.Contract.WorkloadIdentity.Namespace, Name: request.Contract.WorkloadIdentity.ServiceAccount},
		{Verb: "update", Resource: "serviceaccounts", Namespace: request.Contract.WorkloadIdentity.Namespace, Name: request.Contract.WorkloadIdentity.ServiceAccount},
		{Verb: "delete", Resource: "serviceaccounts", Namespace: request.Contract.WorkloadIdentity.Namespace, Name: request.Contract.WorkloadIdentity.ServiceAccount},
		{Verb: "get", Resource: "serviceaccounts", Namespace: request.Contract.WorkloadIdentity.Namespace, Name: distinctProbeLabel(request.Contract.WorkloadIdentity.ServiceAccount, request.NegativeIdentities.WrongServiceAccount.ServiceAccount, request.NegativeIdentities.WrongNamespace.ServiceAccount)},
		{Verb: "create", Resource: "serviceaccounts", Subresource: "token", Namespace: request.Contract.WorkloadIdentity.Namespace, Name: distinctProbeLabel(request.Contract.WorkloadIdentity.ServiceAccount, request.NegativeIdentities.WrongServiceAccount.ServiceAccount, request.NegativeIdentities.WrongNamespace.ServiceAccount)},
		{Verb: "get", Resource: "secrets", Namespace: request.Contract.WorkloadIdentity.Namespace, Name: "cloudring-unrelated"},
		{Verb: "list", Resource: "secrets", Namespace: request.Contract.WorkloadIdentity.Namespace},
		{Verb: "create", Resource: "secrets", Namespace: request.Contract.WorkloadIdentity.Namespace},
		{Verb: "update", Resource: "secrets", Namespace: request.Contract.WorkloadIdentity.Namespace, Name: "cloudring-unrelated"},
		{Verb: "patch", Resource: "secrets", Namespace: request.Contract.WorkloadIdentity.Namespace, Name: "cloudring-unrelated"},
		{Verb: "delete", Resource: "secrets", Namespace: request.Contract.WorkloadIdentity.Namespace, Name: "cloudring-unrelated"},
		{Verb: "get", Resource: "pods", Namespace: request.Contract.WorkloadIdentity.Namespace, Name: "cloudring-unrelated"},
		{Verb: "list", Resource: "pods", Namespace: request.Contract.WorkloadIdentity.Namespace},
		{Verb: "create", Resource: "pods", Subresource: "exec", Namespace: request.Contract.WorkloadIdentity.Namespace, Name: "cloudring-unrelated"},
		{Verb: "create", Group: "batch", Resource: "jobs", Namespace: request.Contract.WorkloadIdentity.Namespace},
		{Verb: "create", Group: "apps", Resource: "deployments", Namespace: request.Contract.WorkloadIdentity.Namespace},
		{Verb: "update", Group: "apps", Resource: "deployments", Namespace: request.Contract.WorkloadIdentity.Namespace, Name: "cloudring-unrelated"},
		{Verb: "create", Group: "rbac.authorization.k8s.io", Resource: "roles", Namespace: request.Contract.WorkloadIdentity.Namespace},
		{Verb: "create", Group: "rbac.authorization.k8s.io", Resource: "rolebindings", Namespace: request.Contract.WorkloadIdentity.Namespace},
		{Verb: "create", Group: "rbac.authorization.k8s.io", Resource: "clusterroles"},
		{Verb: "create", Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings"},
		{Verb: "create", Resource: "namespaces"},
		{Verb: "update", Resource: "namespaces", Name: request.Contract.WorkloadIdentity.Namespace},
		{Verb: "delete", Resource: "namespaces", Name: request.Contract.WorkloadIdentity.Namespace},
	}
	for _, access := range positive {
		allowed, err := client.ReviewAccess(ctx, access)
		if err != nil || !allowed {
			return "", false
		}
	}
	for _, access := range negative {
		allowed, err := client.ReviewAccess(ctx, access)
		if err != nil || allowed {
			return "", false
		}
	}
	return positiveUID, positiveUID != ""
}

func distinctProbeLabel(excluded ...string) string {
	for index := 0; ; index++ {
		candidate := "cloudring-boundary-probe-" + strconv.Itoa(index)
		found := false
		for _, value := range excluded {
			if candidate == value {
				found = true
				break
			}
		}
		if !found {
			return candidate
		}
	}
}

func mountPrestateStillAbsent(ctx context.Context, client OpenBaoClient, token string, request Request) bool {
	c := request.Contract
	reads := []struct {
		path string
		list bool
	}{
		{"sys/auth/" + c.AuthMount, false}, {"auth/" + c.AuthMount + "/config", false},
		{"auth/" + c.AuthMount + "/role", true}, {"sys/policies/acl/" + c.PolicyName, false},
		{"auth/" + c.AuthMount + "/role/" + c.RoleName, false},
		{c.KVV2Mount + "/metadata/" + fullSeedPath(request), false},
	}
	for _, item := range reads {
		var result ReadResult
		var err error
		if item.list {
			result, err = client.List(ctx, token, item.path)
		} else {
			result, err = client.Read(ctx, token, item.path)
		}
		if err != nil || result.Found {
			return false
		}
	}
	kvMount, err := client.Read(ctx, token, "sys/mounts/"+c.KVV2Mount)
	return err == nil && exactKVV2Mount(kvMount)
}

func authMountStillOwned(ctx context.Context, client OpenBaoClient, token string, request Request, plan openbaoauth.Plan, mutations mutationState) bool {
	c := request.Contract
	mount, mountErr := client.Read(ctx, token, "sys/auth/"+c.AuthMount)
	config, configErr := client.Read(ctx, token, "auth/"+c.AuthMount+"/config")
	roles, rolesErr := client.List(ctx, token, "auth/"+c.AuthMount+"/role")
	kvMount, kvMountErr := client.Read(ctx, token, "sys/mounts/"+c.KVV2Mount)
	if mountErr != nil || configErr != nil || rolesErr != nil || kvMountErr != nil || !exactMount(mount, plan.AuthMount) || !exactConfig(config, plan.AuthConfigReadback) || !noForeignRoles(roles, c.RoleName) || !exactKVV2Mount(kvMount) {
		return false
	}
	if mutations.mountCreated && (textValue(mount.Data, "uuid") != mutations.mountUUID || textValue(mount.Data, "accessor") != mutations.mountAccessor) {
		return false
	}
	if mutations.kvMountCreated && (textValue(kvMount.Data, "uuid") != mutations.kvMountUUID || textValue(kvMount.Data, "accessor") != mutations.kvMountAccessor) {
		return false
	}
	return true
}

func kvV2MountStillOwned(ctx context.Context, client OpenBaoClient, token string, request Request, mutations mutationState) bool {
	if !mutations.kvMountCreated {
		return true
	}
	mount, err := client.Read(ctx, token, "sys/mounts/"+request.Contract.KVV2Mount)
	return err == nil && exactKVV2Mount(mount) && textValue(mount.Data, "uuid") == mutations.kvMountUUID && textValue(mount.Data, "accessor") == mutations.kvMountAccessor
}

func provenNonRoot(facts TokenFacts) bool {
	for _, policy := range facts.Policies {
		if policy == "root" {
			return false
		}
	}
	return true
}

func definitelyRejected(err error) bool {
	return errors.Is(err, errDefinitelyRejected) || errors.Is(err, errForbidden)
}

func revokeAndProve(ctx context.Context, client OpenBaoClient, token string) bool {
	if token == "" || ctx.Err() != nil {
		return false
	}
	if _, err := client.LookupSelf(ctx, token); err != nil {
		return false
	}
	// A lost response or a 5xx can follow a committed self-revoke. The fixed
	// post-denial probe is the authority: cleanup succeeds only when the same
	// credential is now rejected, regardless of the write response.
	_, _ = client.Write(ctx, token, "auth/token/revoke-self", map[string]any{})
	return client.ExpectForbidden(ctx, http.MethodGet, token, "auth/token/lookup-self", nil) == nil
}

func managementPaths(request Request) map[string][]string {
	delegation, _ := openbaobootstrap.BuildManagementDelegation(request.Contract, request.ManagementPolicyName, request.Seed.RelativePath)
	return delegation.Paths
}

func exactManagementPolicy(result ReadResult, name, body string) bool {
	if !result.Found || len(result.Data) != 5 || textValue(result.Data, "name") != name || textValue(result.Data, "policy") != body || !validStableTimestamp(textValue(result.Data, "modified")) {
		return false
	}
	casRequired, casOK := result.Data["cas_required"].(bool)
	version, versionOK := integer(result.Data, "version")
	return casOK && !casRequired && versionOK && version >= 1
}

func exactManagementCapabilities(actual, expected map[string][]string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for path, want := range expected {
		if !equalStrings(actual[path], want) {
			return false
		}
	}
	return true
}

func verifyWorkloadAuthorization(ctx context.Context, kubernetes KubernetesClient, openBao OpenBaoClient, request Request, positiveServiceAccountUID string, seedData map[string]any) (gate string, cleanupSafe bool) {
	cleanupSafe = true
	contract := request.Contract
	currentServiceAccount, err := kubernetes.GetServiceAccount(ctx, contract.WorkloadIdentity.Namespace, contract.WorkloadIdentity.ServiceAccount)
	if err != nil || currentServiceAccount.UID != positiveServiceAccountUID {
		return "positive-service-account-changed", true
	}
	positiveToken, err := kubernetes.RequestServiceAccountToken(ctx, contract.WorkloadIdentity.Namespace, contract.WorkloadIdentity.ServiceAccount, contract.Audience, 600)
	if err != nil || !validServiceAccountToken(positiveToken, 600) {
		return "positive-tokenrequest", true
	}
	loginPath := "auth/" + contract.AuthMount + "/login"
	login, err := openBao.Write(ctx, "", loginPath, map[string]any{"role": contract.RoleName, "jwt": positiveToken.JWT})
	if err != nil {
		return "positive-login", definitelyRejected(err)
	}
	workloadToken := textValue(login.Auth, "client_token")
	if workloadToken == "" {
		return "positive-login", false
	}
	defer func() {
		if workloadToken != "" {
			if !revokeAndProve(context.WithoutCancel(ctx), openBao, workloadToken) {
				cleanupSafe = false
			}
		}
	}()
	if !exactLogin(login.Auth, contract, positiveServiceAccountUID) {
		return "positive-login", true
	}
	seedPath := fullSeedPath(request)
	seed, err := openBao.Read(ctx, workloadToken, contract.KVV2Mount+"/data/"+seedPath)
	if err != nil || !seed.Found || !exactSeedData(seed, seedData) {
		return "allowed-data-read", true
	}
	siblingPath := contract.KVV2Mount + "/data/" + contract.DataPrefix + "-denied/" + request.Seed.RelativePath
	metadataPath := contract.KVV2Mount + "/metadata/" + seedPath
	paths := []string{
		contract.KVV2Mount + "/data/" + seedPath, siblingPath, metadataPath, contract.KVV2Mount + "/metadata/" + contract.DataPrefix,
		"auth/token/lookup-self", "auth/token/revoke-self", "sys/capabilities-self", "auth/token/renew-self",
	}
	caps, err := openBao.CapabilitiesSelf(ctx, workloadToken, paths)
	if err != nil || !equalStrings(caps[paths[0]], []string{"read"}) || !equalStrings(caps[paths[1]], []string{"deny"}) || !equalStrings(caps[paths[2]], []string{"deny"}) || !equalStrings(caps[paths[3]], []string{"deny"}) ||
		!equalStrings(caps[paths[4]], []string{"read"}) || !equalStrings(caps[paths[5]], []string{"update"}) || !equalStrings(caps[paths[6]], []string{"update"}) || !equalStrings(caps[paths[7]], []string{"deny"}) {
		return "workload-capability-boundary", true
	}
	if err := openBao.ExpectForbidden(ctx, http.MethodGet, workloadToken, siblingPath, nil); err != nil {
		return "sibling-path-denial", true
	}
	if err := openBao.ExpectForbidden(ctx, http.MethodGet, workloadToken, metadataPath, nil); err != nil {
		return "metadata-denial", true
	}
	negative := []struct{ namespace, serviceAccount, audience string }{
		{contract.WorkloadIdentity.Namespace, contract.WorkloadIdentity.ServiceAccount, "cloudring-invalid"},
		{request.NegativeIdentities.WrongServiceAccount.Namespace, request.NegativeIdentities.WrongServiceAccount.ServiceAccount, contract.Audience},
		{request.NegativeIdentities.WrongNamespace.Namespace, request.NegativeIdentities.WrongNamespace.ServiceAccount, contract.Audience},
	}
	for _, test := range negative {
		projectedToken, err := kubernetes.RequestServiceAccountToken(ctx, test.namespace, test.serviceAccount, test.audience, 600)
		if err != nil || !validServiceAccountToken(projectedToken, 600) {
			return "negative-tokenrequest", true
		}
		negativeLogin, loginErr := openBao.Write(ctx, "", loginPath, map[string]any{"role": contract.RoleName, "jwt": projectedToken.JWT})
		if errors.Is(loginErr, errForbidden) {
			continue
		}
		if loginErr != nil {
			return "negative-login-denial", !errors.Is(loginErr, errMutationAmbiguous)
		}
		unexpectedToken := textValue(negativeLogin.Auth, "client_token")
		if unexpectedToken == "" || !revokeAndProve(context.WithoutCancel(ctx), openBao, unexpectedToken) {
			return "negative-login-denial", false
		}
		return "negative-login-denial", true
	}
	revokedToken := workloadToken
	if !revokeAndProve(ctx, openBao, revokedToken) {
		return "workload-token-revoke", false
	}
	workloadToken = ""
	return "", true
}

func validServiceAccountToken(token ServiceAccountToken, requestedSeconds int64) bool {
	if len(token.JWT) < 8 || token.ExpirationTimestamp.IsZero() || requestedSeconds <= 0 {
		return false
	}
	remaining := time.Until(token.ExpirationTimestamp)
	return remaining >= time.Duration(requestedSeconds-60)*time.Second && remaining <= time.Duration(requestedSeconds+30)*time.Second
}

func rollback(ctx context.Context, client OpenBaoClient, token string, request Request, plan openbaoauth.Plan, state mutationState) bool {
	if ctx.Err() != nil {
		return false
	}
	if state.seedCreated {
		return false
	}
	if !kvV2MountStillOwned(ctx, client, token, request, state) {
		return false
	}
	if state.roleCreated {
		if ctx.Err() != nil {
			return false
		}
		path := "auth/" + request.Contract.AuthMount + "/role/" + request.Contract.RoleName
		role, err := client.Read(ctx, token, path)
		if err != nil || !exactRole(role, plan.Role) {
			return false
		}
		_ = client.Delete(ctx, token, path)
		role, err = client.Read(ctx, token, path)
		if err != nil || role.Found {
			return false
		}
	}
	if state.policyCreated {
		if ctx.Err() != nil {
			return false
		}
		path := "sys/policies/acl/" + request.Contract.PolicyName
		policy, err := client.Read(ctx, token, path)
		version, ok := integer(policy.Data, "version")
		if err != nil || !exactPolicy(policy, request.Contract.PolicyName, plan.ACLPolicy) || !ok || version != state.policyVersion || textValue(policy.Data, "modified") != state.policyModified {
			return false
		}
		_ = client.Delete(ctx, token, path)
		policy, err = client.Read(ctx, token, path)
		if err != nil || policy.Found {
			return false
		}
	}
	if state.mountCreated {
		if ctx.Err() != nil {
			return false
		}
		mountPath := "sys/auth/" + request.Contract.AuthMount
		mount, err := client.Read(ctx, token, mountPath)
		config, configErr := client.Read(ctx, token, "auth/"+request.Contract.AuthMount+"/config")
		roles, rolesErr := client.List(ctx, token, "auth/"+request.Contract.AuthMount+"/role")
		configSafe := !config.Found || exactConfig(config, plan.AuthConfigReadback)
		if err != nil || configErr != nil || rolesErr != nil || !exactMount(mount, plan.AuthMount) ||
			textValue(mount.Data, "uuid") != state.mountUUID || textValue(mount.Data, "accessor") != state.mountAccessor ||
			!configSafe || !noRoles(roles) {
			return false
		}
		_ = client.Delete(ctx, token, mountPath)
		mount, err = client.Read(ctx, token, mountPath)
		if err != nil || mount.Found {
			return false
		}
	}
	return true
}

func unchangedBeforeWrite(ctx context.Context, client OpenBaoClient, token, path string, prior ReadResult) bool {
	current, err := client.Read(ctx, token, path)
	return err == nil && current.Found == prior.Found && (!current.Found || equalJSON(current.Data, prior.Data))
}

func exactMount(result ReadResult, desired openbaoauth.AuthMountDesired) bool {
	if !result.Found || len(result.Data) != 13 || textValue(result.Data, "type") != desired.Type || textValue(result.Data, "description") != desired.Description ||
		textValue(result.Data, "uuid") == "" || textValue(result.Data, "accessor") == "" ||
		textValue(result.Data, "plugin_version") != "" || textValue(result.Data, "running_plugin_version") != "v"+supportedOpenBaoVersion+"+builtin.bao" ||
		textValue(result.Data, "running_sha256") != "" || textValue(result.Data, "deprecation_status") != "supported" || !emptyOptions(result.Data["options"]) {
		return false
	}
	for _, field := range []string{"local", "seal_wrap", "external_entropy_access"} {
		value, ok := result.Data[field].(bool)
		if !ok || value {
			return false
		}
	}
	config, ok := object(result.Data, "config")
	if !ok || len(config) != 4 || textValue(config, "token_type") != "default-service" {
		return false
	}
	defaultTTL, defaultOK := integer(config, "default_lease_ttl")
	maxTTL, maxOK := integer(config, "max_lease_ttl")
	forceNoCache, forceOK := config["force_no_cache"].(bool)
	return defaultOK && maxOK && forceOK && defaultTTL == 0 && maxTTL == 0 && !forceNoCache
}

func emptyOptions(value any) bool {
	if value == nil {
		return true
	}
	options, ok := value.(map[string]any)
	return ok && len(options) == 0
}

func exactConfig(result ReadResult, desired openbaoauth.KubernetesConfigReadbackExpected) bool {
	if !result.Found {
		return false
	}
	want := desiredMap(desired)
	return exactFields(result.Data, want)
}

func exactPolicy(result ReadResult, name string, desired openbaoauth.ACLPolicyDesired) bool {
	if !result.Found || len(result.Data) != 5 || textValue(result.Data, "name") != name || textValue(result.Data, "policy") != desired.Policy || !validStableTimestamp(textValue(result.Data, "modified")) {
		return false
	}
	casRequired, ok := result.Data["cas_required"].(bool)
	version, versionOK := integer(result.Data, "version")
	return ok && casRequired == desired.CASRequired && versionOK && version >= 1
}

func exactRole(result ReadResult, desired openbaoauth.KubernetesRoleDesired) bool {
	if !result.Found {
		return false
	}
	expected := desiredMap(desired)
	expected["token_ttl"] = json.Number("600")
	expected["token_max_ttl"] = json.Number("1800")
	expected["token_explicit_max_ttl"] = json.Number("1800")
	return exactFields(result.Data, expected)
}

func exactKVV2Mount(result ReadResult) bool {
	if !result.Found || len(result.Data) != 13 || textValue(result.Data, "type") != "kv" || textValue(result.Data, "uuid") == "" || textValue(result.Data, "accessor") == "" ||
		textValue(result.Data, "plugin_version") != "" || textValue(result.Data, "running_plugin_version") != "v"+supportedOpenBaoVersion+"+builtin.bao" ||
		textValue(result.Data, "running_sha256") != "" || textValue(result.Data, "deprecation_status") != "supported" {
		return false
	}
	options, ok := object(result.Data, "options")
	config, configOK := object(result.Data, "config")
	local, localOK := result.Data["local"].(bool)
	sealWrap, sealOK := result.Data["seal_wrap"].(bool)
	externalEntropy, externalOK := result.Data["external_entropy_access"].(bool)
	description, descriptionOK := result.Data["description"].(string)
	defaultTTL, defaultOK := integer(config, "default_lease_ttl")
	maxTTL, maxOK := integer(config, "max_lease_ttl")
	forceNoCache, forceOK := config["force_no_cache"].(bool)
	return ok && len(options) == 1 && textValue(options, "version") == "2" && configOK && len(config) == 3 &&
		localOK && !local && sealOK && !sealWrap && externalOK && !externalEntropy && descriptionOK && description == "" &&
		defaultOK && defaultTTL == 0 && maxOK && maxTTL == 0 && forceOK && !forceNoCache
}

func noForeignRoles(result ReadResult, desired string) bool {
	if !result.Found {
		return true
	}
	keys, ok := stringSlice(result.Data, "keys")
	return ok && (len(keys) == 0 || equalStrings(keys, []string{desired}))
}

func noRoles(result ReadResult) bool {
	if !result.Found {
		return true
	}
	keys, ok := stringSlice(result.Data, "keys")
	return ok && len(keys) == 0
}

func readExactSeed(ctx context.Context, client OpenBaoClient, token string, request Request, seedData map[string]any) (ReadResult, ReadResult, bool) {
	path := fullSeedPath(request)
	metadata, err := client.Read(ctx, token, request.Contract.KVV2Mount+"/metadata/"+path)
	if err != nil {
		return ReadResult{}, ReadResult{}, false
	}
	seed, err := client.Read(ctx, token, request.Contract.KVV2Mount+"/data/"+path)
	_, exact := exactSeed(metadata, seed, seedData)
	return metadata, seed, err == nil && exact
}

func exactSeed(metadata, seed ReadResult, expected map[string]any) (string, bool) {
	if !metadata.Found || !seed.Found {
		return "", false
	}
	if len(metadata.Data) != 11 || metadata.Data["custom_metadata"] != nil {
		return "", false
	}
	currentVersion, currentOK := integer(metadata.Data, "current_version")
	metadataVersion, metadataOK := integer(metadata.Data, "current_metadata_version")
	oldestVersion, oldestOK := integer(metadata.Data, "oldest_version")
	maxVersions, maxOK := integer(metadata.Data, "max_versions")
	casRequired, casOK := metadata.Data["cas_required"].(bool)
	metadataCASRequired, metadataCASOK := metadata.Data["metadata_cas_required"].(bool)
	createdAt, updatedAt := textValue(metadata.Data, "created_time"), textValue(metadata.Data, "updated_time")
	if !currentOK || currentVersion < 1 || !metadataOK || metadataVersion != 0 || !oldestOK || (oldestVersion != 0 && (oldestVersion < 1 || oldestVersion > currentVersion)) ||
		!maxOK || maxVersions != 0 || !casOK || casRequired || !metadataCASOK || metadataCASRequired ||
		textValue(metadata.Data, "delete_version_after") != "0s" || !validStableTimestamp(createdAt) || !validStableTimestamp(updatedAt) {
		return "", false
	}
	createdTime, _ := time.Parse(time.RFC3339Nano, createdAt)
	updatedTime, _ := time.Parse(time.RFC3339Nano, updatedAt)
	if updatedTime.Before(createdTime) {
		return "", false
	}
	versions, ok := object(metadata.Data, "versions")
	if !ok || len(versions) == 0 || int64(len(versions)) > currentVersion {
		return "", false
	}
	for key, rawVersion := range versions {
		version, err := strconv.ParseInt(key, 10, 64)
		versionFacts, versionOK := rawVersion.(map[string]any)
		if err != nil || version < 1 || version > currentVersion || !versionOK || len(versionFacts) != 3 ||
			!validStableTimestamp(textValue(versionFacts, "created_time")) {
			return "", false
		}
		deletionTime := textValue(versionFacts, "deletion_time")
		if deletionTime != "" && !validStableTimestamp(deletionTime) {
			return "", false
		}
		if _, destroyedOK := versionFacts["destroyed"].(bool); !destroyedOK {
			return "", false
		}
	}
	current, ok := object(versions, strconv.FormatInt(currentVersion, 10))
	destroyed, destroyedOK := current["destroyed"].(bool)
	if !ok || !destroyedOK || destroyed || textValue(current, "deletion_time") != "" ||
		textValue(current, "created_time") != updatedAt ||
		!exactSeedDataAt(seed, expected, updatedAt, currentVersion) {
		return "", false
	}
	return updatedAt, true
}

func exactSeedData(seed ReadResult, expected map[string]any) bool {
	if !seed.Found {
		return false
	}
	metadata, ok := object(seed.Data, "metadata")
	version, versionOK := integer(metadata, "version")
	return ok && versionOK && version >= 1 && exactSeedDataAt(seed, expected, textValue(metadata, "created_time"), version)
}

func exactSeedDataAt(seed ReadResult, expected map[string]any, createdAt string, expectedVersion int64) bool {
	if len(seed.Data) != 2 {
		return false
	}
	data, ok := object(seed.Data, "data")
	if !ok || !equalJSON(data, expected) {
		return false
	}
	metadata, ok := object(seed.Data, "metadata")
	if !ok || len(metadata) != 5 || metadata["custom_metadata"] != nil || textValue(metadata, "created_time") != createdAt || !validStableTimestamp(createdAt) {
		return false
	}
	version, ok := integer(metadata, "version")
	destroyed, destroyedOK := metadata["destroyed"].(bool)
	return ok && expectedVersion >= 1 && version == expectedVersion && destroyedOK && !destroyed && textValue(metadata, "deletion_time") == ""
}

func exactSeedWrite(result ReadResult, createdAt string) bool {
	if !result.Found || len(result.Data) != 5 || result.Data["custom_metadata"] != nil || textValue(result.Data, "created_time") != createdAt || textValue(result.Data, "deletion_time") != "" {
		return false
	}
	version, versionOK := integer(result.Data, "version")
	destroyed, destroyedOK := result.Data["destroyed"].(bool)
	return versionOK && version == 1 && destroyedOK && !destroyed && validStableTimestamp(createdAt)
}

func validStableTimestamp(value string) bool {
	if value == "" {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}

func exactLogin(auth map[string]any, contract openbaoauth.Contract, serviceAccountUID string) bool {
	if len(auth) != 12 || !safeOpaque(textValue(auth, "client_token"), 8, 64*1024) || !safeOpaque(textValue(auth, "accessor"), 8, 512) ||
		textValue(auth, "entity_id") == "" || textValue(auth, "token_type") != "service" || auth["mfa_requirement"] != nil {
		return false
	}
	policies, ok := stringSlice(auth, "policies")
	tokenPolicies, tokenPoliciesOK := stringSlice(auth, "token_policies")
	if !ok || !tokenPoliciesOK || !equalStrings(policies, []string{contract.PolicyName}) || !equalStrings(tokenPolicies, []string{contract.PolicyName}) {
		return false
	}
	duration, ok := integer(auth, "lease_duration")
	numUses, usesOK := integer(auth, "num_uses")
	orphan, orphanOK := auth["orphan"].(bool)
	renewable, renewableOK := auth["renewable"].(bool)
	if !ok || duration != 600 || !usesOK || numUses != 0 || !orphanOK || !orphan || !renewableOK || !renewable {
		return false
	}
	metadata, ok := object(auth, "metadata")
	return ok && len(metadata) == 5 && textValue(metadata, "service_account_name") == contract.WorkloadIdentity.ServiceAccount &&
		textValue(metadata, "service_account_namespace") == contract.WorkloadIdentity.Namespace && textValue(metadata, "service_account_uid") == serviceAccountUID &&
		textValue(metadata, "service_account_secret_name") == "" && textValue(metadata, "role") == contract.RoleName
}

func exactFields(actual, expected map[string]any) bool {
	if len(actual) != len(expected) {
		return false
	}
	for key, want := range expected {
		got, ok := actual[key]
		if !ok || !equalJSON(got, want) {
			return false
		}
	}
	return true
}

func desiredMap(value any) map[string]any {
	data, _ := json.Marshal(value)
	var result map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	_ = decoder.Decode(&result)
	return result
}

func decodedSeed(seed Seed) (map[string]any, bool) {
	result := make(map[string]any, len(seed.Entries))
	for _, entry := range seed.Entries {
		value, err := base64.StdEncoding.Strict().DecodeString(entry.ValueBase64)
		if err != nil {
			return nil, false
		}
		result[entry.Key] = string(value)
		zeroBytes(value)
	}
	return result, true
}

func fullSeedPath(request Request) string {
	return request.Contract.DataPrefix + "/" + request.Seed.RelativePath
}

func orderedKeys(values map[string][]string) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy, rightCopy := append([]string{}, left...), append([]string{}, right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] {
			return false
		}
	}
	return true
}

func equalJSON(left, right any) bool {
	leftData, leftErr := json.Marshal(left)
	rightData, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftData) == string(rightData)
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func fixedReport(status Status, mutated, rollback bool, failedGate string, completed []string) Report {
	return Report{
		SchemaVersion: SchemaVersion, Status: status, MutationPerformed: mutated,
		RollbackAttempted: rollback, InputMaterialEchoed: false,
		CompletedGates: append([]string{}, completed...), FailedGate: failedGate,
		NonClaims: append([]string{}, reportNonClaims...),
	}
}
