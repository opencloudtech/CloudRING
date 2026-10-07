// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package openbaoauth

import (
	"fmt"
)

const authMountLifecycleMutationGate = "auth-mount-lifecycle-allows-mutation"

var requiredLiveGates = []string{
	"openbao-active-unsealed-healthy",
	"local-reviewer-token-ca-and-tokenreview-proven",
	"auth-mount-type-and-config-prestate-captured",
	"dedicated-auth-mount-ownership-proven",
	"dedicated-auth-mount-has-no-foreign-roles-proven",
	"config-write-limited-to-auth-mount-created-by-current-run",
	"mount-and-config-state-unchanged-under-exclusive-lock",
	"static-reviewer-jwt-absent",
	"deprecated-issuer-config-prestate-captured",
	"kv-v2-mount-absent-or-exact-prestate-captured",
	"kv-v2-mount-create-only-initialization-and-readback-proven",
	"policy-cas-prestate-captured",
	"role-prestate-captured-and-drift-fails-closed",
	"exclusive-operator-lock-covers-all-non-cas-writes-and-readbacks",
	"existing-auth-mount-with-absent-or-drifted-config-blocks-before-mutation",
	"only-current-run-owned-auth-mount-may-be-disabled-during-rollback",
	"positive-login-and-exact-policy-ttl-proven",
	"wrong-audience-serviceaccount-namespace-and-path-denied",
	"metadata-and-list-denied",
	"eso-tokenrequest-path-proven-without-legacy-token-secret",
	"secretstore-canary-sync-rotation-revocation-and-audit-proven",
}

var nonClaims = []string{
	"no OpenBao API request was performed",
	"no Kubernetes API request was performed",
	"no authentication mount, policy, or role was applied",
	"no dedicated authentication-mount ownership was proven",
	"no SecretStore or ExternalSecret readiness was proven",
	"no production or live readiness is claimed",
	"the sanitized report does not bind a target and is not an approval receipt",
}

var fixedProfile = ProfileSummary{
	AuthType: "kubernetes", AuthMountOwnership: DedicatedAuthMountOwnership,
	KubernetesHostMode: "in-cluster-service-dns",
	ReviewerSourceMode: "pod-local-rotating-service-account",
	Audience:           "openbao", AliasNameSource: "serviceaccount_uid",
	Capabilities: []string{"read"}, BoundIdentityCount: 1,
	TokenTTL: "10m", TokenMaxTTL: "30m", TokenNoDefaultPolicy: true,
}

// Build validates the complete contract and creates the deterministic
// source-only desired-state plan. Callers cannot bypass the profile validator.
func Build(contract Contract) (Plan, []Problem) {
	if problems := Validate(contract); len(problems) != 0 {
		return Plan{}, problems
	}
	policy := fmt.Sprintf("path %q {\n  capabilities = [\"read\"]\n}\npath \"auth/token/lookup-self\" {\n  capabilities = [\"read\"]\n}\npath \"auth/token/revoke-self\" {\n  capabilities = [\"update\"]\n}\npath \"sys/capabilities-self\" {\n  capabilities = [\"update\"]\n}\n", contract.KVV2Mount+"/data/"+contract.DataPrefix+"/*")
	authMount := AuthMountDesired{Type: "kubernetes", Description: "CloudRING dedicated Kubernetes workload authentication for " + contract.RoleName}
	config := KubernetesConfigDesired{
		KubernetesHost: "https://kubernetes.default.svc", KubernetesCACert: "", TokenReviewerJWT: "",
		PEMKeys: []string{}, Issuer: "", DisableISSValidation: true, DisableLocalCAJWT: false,
	}
	configReadback := KubernetesConfigReadbackExpected{
		KubernetesHost: config.KubernetesHost, KubernetesCACert: config.KubernetesCACert,
		PEMKeys: []string{}, Issuer: config.Issuer, DisableISSValidation: config.DisableISSValidation,
		DisableLocalCAJWT: config.DisableLocalCAJWT, TokenReviewerJWTSet: false,
	}
	kvV2Mount := KVV2MountDesired{Type: "kv", Description: "", Options: map[string]string{"version": "2"}}
	aclPolicy := ACLPolicyDesired{Policy: policy, CAS: -1, CASRequired: true}
	role := KubernetesRoleDesired{
		BoundServiceAccountNames:             []string{contract.WorkloadIdentity.ServiceAccount},
		BoundServiceAccountNamespaces:        []string{contract.WorkloadIdentity.Namespace},
		BoundServiceAccountNamespaceSelector: "", Audience: contract.Audience,
		AliasNameSource: contract.AliasNameSource, TokenPolicies: []string{contract.PolicyName},
		TokenNoDefaultPolicy: contract.TokenNoDefaultPolicy, TokenTTL: contract.TokenTTL,
		TokenMaxTTL: contract.TokenMaxTTL, TokenExplicitMaxTTL: contract.TokenMaxTTL,
		TokenType: "service", TokenNumUses: 0, TokenPeriod: 0, TokenBoundCIDRs: []string{},
		TokenStrictlyBindIP: false,
	}
	authMountStates := authMountStateRules()
	mutationGate := MutationGate{ID: authMountLifecycleMutationGate, AllowedDecisions: []AuthMountDecision{AuthMountCreateOwned, AuthMountReuseExact}}
	actions := []Action{
		{ID: "read-auth-mount", Method: "GET", EndpointClass: "auth-mount", Target: contract.AuthMount, PreStateRequired: true, CASMode: "none"},
		{ID: "read-kubernetes-auth-config", Method: "GET", EndpointClass: "kubernetes-auth-config", Target: contract.AuthMount, PreStateRequired: true, CASMode: "none"},
		{ID: "list-kubernetes-auth-roles", Method: "LIST", EndpointClass: "kubernetes-auth-roles", Target: contract.AuthMount, PreStateRequired: true, CASMode: "none", FailClosedPrecondition: "preexisting-mount-must-have-no-foreign-roles"},
		{ID: "read-kv-v2-mount", Method: "GET", EndpointClass: "secret-mount", Target: contract.KVV2Mount, PreStateRequired: true, CASMode: "none", FailClosedPrecondition: "mount-type-must-be-kv-with-version-two"},
		{ID: "read-acl-policy", Method: "GET", EndpointClass: "acl-policy", Target: contract.PolicyName, PreStateRequired: true, CASMode: "none"},
		{ID: "read-kubernetes-auth-role", Method: "GET", EndpointClass: "kubernetes-auth-role", Target: contract.AuthMount + "\x00" + contract.RoleName, PreStateRequired: true, CASMode: "none"},
		{ID: "initialize-kv-v2-mount-if-absent", Method: "POST", EndpointClass: "secret-mount", Target: contract.KVV2Mount, Mutates: true, Conditional: true, PreStateRequired: true, RunCondition: "kv-v2-mount-state-equals-absent", GlobalMutationGate: authMountLifecycleMutationGate, MutationGuard: "exclusive-lock-held-and-complete-prestate-unchanged", RollbackMode: "retain-current-run-created-empty-mount;automatic-delete-forbidden", CASMode: "api-cas-unavailable-exclusive-lock", DesiredState: kvV2Mount, FailClosedPrecondition: "mount-must-be-absent-or-exact-kv-version-two", ChangeRequiresApproval: true},
		{ID: "readback-kv-v2-mount", Method: "GET", EndpointClass: "secret-mount", Target: contract.KVV2Mount, Conditional: true, PreStateRequired: true, CASMode: "exact-post-write-readback", DesiredState: kvV2Mount, FailClosedPrecondition: "mount-type-version-defaults-uuid-and-accessor-must-match"},
		{ID: "create-dedicated-auth-mount-if-absent", Method: "POST", EndpointClass: "auth-mount", Target: contract.AuthMount, Mutates: true, Conditional: true, PreStateRequired: true, RollbackRequired: true, RunCondition: "auth-mount-state-equals-absent", GlobalMutationGate: authMountLifecycleMutationGate, MutationGuard: "exclusive-lock-held-and-prestate-unchanged", RollbackMode: "disable-only-current-run-created-mount-after-exact-ownership-readback", CASMode: "api-cas-unavailable-exclusive-lock", DesiredState: authMount, FailClosedPrecondition: "mount-must-be-absent-or-exact-dedicated-owned-state-with-exact-config", ChangeRequiresApproval: true},
		{ID: "readback-auth-mount", Method: "GET", EndpointClass: "auth-mount", Target: contract.AuthMount, Conditional: true, PreStateRequired: true, CASMode: "exact-post-write-readback", DesiredState: authMount, FailClosedPrecondition: "mount-type-and-contract-bound-description-must-match"},
		{ID: "configure-local-reviewer-only-on-created-mount", Method: "POST", EndpointClass: "kubernetes-auth-config", Target: contract.AuthMount, Mutates: true, Conditional: true, PreStateRequired: true, RollbackRequired: true, RunCondition: "create-dedicated-auth-mount-outcome-equals-created-by-current-execution", GlobalMutationGate: authMountLifecycleMutationGate, MutationGuard: "auth-mount-created-by-current-run", RollbackMode: "disable-auth-mount-only-if-created-by-current-execution", CASMode: "api-cas-unavailable-exclusive-lock", DesiredState: config, FailClosedPrecondition: "preexisting-config-must-be-exact;absent-on-preexisting-mount-blocks", ChangeRequiresApproval: true},
		{ID: "readback-kubernetes-auth-config", Method: "GET", EndpointClass: "kubernetes-auth-config", Target: contract.AuthMount, Conditional: true, PreStateRequired: true, CASMode: "exact-post-write-readback", DesiredState: configReadback, FailClosedPrecondition: "config-and-token-reviewer-jwt-set-false-must-match-complete-v2-5-5-readback"},
		{ID: "create-acl-policy-if-absent", Method: "POST", EndpointClass: "acl-policy", Target: contract.PolicyName, Mutates: true, Conditional: true, PreStateRequired: true, RollbackRequired: true, RunCondition: "all-prestate-and-prior-write-readbacks-succeeded", GlobalMutationGate: authMountLifecycleMutationGate, RollbackMode: "delete-only-current-run-created-policy-after-exact-version-and-body-readback", CASMode: "create-only-cas-minus-one", DesiredState: aclPolicy, FailClosedPrecondition: "existing-policy-drift-must-block", ChangeRequiresApproval: true},
		{ID: "readback-acl-policy", Method: "GET", EndpointClass: "acl-policy", Target: contract.PolicyName, Conditional: true, PreStateRequired: true, CASMode: "exact-post-write-readback", FailClosedPrecondition: "policy-body-cas-mode-and-version-must-match"},
		{ID: "create-role-if-absent", Method: "POST", EndpointClass: "kubernetes-auth-role", Target: contract.AuthMount + "\x00" + contract.RoleName, Mutates: true, Conditional: true, PreStateRequired: true, RollbackRequired: true, RunCondition: "all-prestate-and-prior-write-readbacks-succeeded", GlobalMutationGate: authMountLifecycleMutationGate, RollbackMode: "delete-only-current-run-created-role-after-exact-readback", CASMode: "api-cas-unavailable-exclusive-lock", DesiredState: role, FailClosedPrecondition: "existing-role-drift-must-block", ChangeRequiresApproval: true},
		{ID: "readback-kubernetes-auth-role", Method: "GET", EndpointClass: "kubernetes-auth-role", Target: contract.AuthMount + "\x00" + contract.RoleName, Conditional: true, PreStateRequired: true, CASMode: "exact-post-write-readback", FailClosedPrecondition: "role-must-match-complete-desired-state"},
	}
	return Plan{AuthMountOwnership: contract.AuthMountOwnership, AuthMountStates: authMountStates, MutationGate: mutationGate, KVV2Mount: kvV2Mount, AuthMount: authMount, AuthConfig: config, AuthConfigReadback: configReadback, ACLPolicy: aclPolicy, Role: role, Actions: actions}, nil
}

// DecideAuthMountLifecycle returns the fixed fail-closed decision for a
// normalized pre-state. An unknown state is never interpreted as absence.
func DecideAuthMountLifecycle(state AuthMountPreState) (AuthMountStateRule, bool) {
	for _, rule := range authMountStateRules() {
		if rule.PreState == state {
			return rule, true
		}
	}
	return AuthMountStateRule{}, false
}

// Allows reports whether a known lifecycle decision may reach any mutating
// action. Blocked and unknown decisions fail closed.
func (gate MutationGate) Allows(decision AuthMountDecision) bool {
	for _, allowed := range gate.AllowedDecisions {
		if decision == allowed {
			return true
		}
	}
	return false
}

func authMountStateRules() []AuthMountStateRule {
	return []AuthMountStateRule{
		{PreState: AuthMountAbsent, Decision: AuthMountCreateOwned, Mutates: true, RollbackMode: "disable-current-run-created-mount-after-exact-ownership-readback"},
		{PreState: AuthMountPresentExact, Decision: AuthMountReuseExact, RollbackMode: "none"},
		{PreState: AuthMountPresentConfigAbsent, Decision: AuthMountBlock, RollbackMode: "none"},
		{PreState: AuthMountPresentConfigDrifted, Decision: AuthMountBlock, RollbackMode: "none"},
		{PreState: AuthMountPresentTypeOrDescDrift, Decision: AuthMountBlock, RollbackMode: "none"},
		{PreState: AuthMountUnknownIncompleteUnavailableOrChanged, Decision: AuthMountBlock, RollbackMode: "none"},
	}
}

// buildReport produces the evidence-safe projection used by the CLI. It stays
// private so callers cannot inject arbitrary display fields into the report.
// It deliberately emits no hashes of low-entropy provider identifiers: such
// hashes are reversible by offline enumeration and are not anonymization.
func buildReport(plan Plan) Report {
	summaries := make([]ActionSummary, 0, len(plan.Actions))
	for _, action := range plan.Actions {
		summary := ActionSummary{
			ID: action.ID, Method: action.Method, EndpointClass: action.EndpointClass,
			Mutates: action.Mutates, Conditional: action.Conditional,
			PreStateRequired: action.PreStateRequired, RollbackRequired: action.RollbackRequired,
			RunCondition: action.RunCondition, GlobalMutationGate: action.GlobalMutationGate, MutationGuard: action.MutationGuard,
			RollbackMode: action.RollbackMode,
			CASMode:      action.CASMode, FailClosedPrecondition: action.FailClosedPrecondition,
			ChangeApprovalRequired: action.ChangeRequiresApproval,
		}
		summaries = append(summaries, summary)
	}
	return Report{
		SchemaVersion: SchemaVersion, Mode: "plan", Status: "planned",
		MutationPerformed: false, ApplyAuthorized: false, ApplyApprovalNeeded: true, InputMaterialEchoed: false,
		IdentifierFingerprintsEmitted: false,
		Profile:                       cloneFixedProfile(),
		Actions:                       summaries, RequiredLiveGates: append([]string{}, requiredLiveGates...),
		NonClaims: append([]string{}, nonClaims...),
	}
}

func blockedReport(problems []Problem) Report {
	return Report{
		SchemaVersion: SchemaVersion, Mode: "plan", Status: "blocked",
		MutationPerformed: false, ApplyAuthorized: false, ApplyApprovalNeeded: true, InputMaterialEchoed: false,
		IdentifierFingerprintsEmitted: false,
		Profile:                       cloneFixedProfile(),
		Blockers:                      append([]Problem{}, problems...), RequiredLiveGates: append([]string{}, requiredLiveGates...),
		NonClaims: append([]string{}, nonClaims...),
	}
}

func cloneFixedProfile() ProfileSummary {
	profile := fixedProfile
	profile.Capabilities = append([]string{}, fixedProfile.Capabilities...)
	return profile
}
