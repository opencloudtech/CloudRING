// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package openbaoauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestEvaluateBuildsDeterministicSanitizedPlan(t *testing.T) {
	input := validJSON(t)
	first, err := Evaluate(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	second, err := Evaluate(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("Evaluate() second error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("Evaluate() is not deterministic")
	}
	if first.Status != "planned" || first.Mode != "plan" || len(first.Actions) != 16 {
		t.Fatalf("unexpected report status/mode/actions: %#v", first)
	}
	if first.MutationPerformed || first.ApplyAuthorized || !first.ApplyApprovalNeeded || first.InputMaterialEchoed ||
		first.IdentifierFingerprintsEmitted {
		t.Fatalf("plan made an unsafe claim: %#v", first)
	}
	if got := findActionSummary(t, first.Actions, "configure-local-reviewer-only-on-created-mount"); got.MutationGuard != "auth-mount-created-by-current-run" ||
		got.RunCondition != "create-dedicated-auth-mount-outcome-equals-created-by-current-execution" ||
		got.GlobalMutationGate != authMountLifecycleMutationGate ||
		got.RollbackMode != "disable-auth-mount-only-if-created-by-current-execution" {
		t.Fatalf("sanitized report omitted fixed ownership guards: %#v", got)
	}
	if first.Profile.AuthType != "kubernetes" || first.Profile.KubernetesHostMode != "in-cluster-service-dns" ||
		first.Profile.AuthMountOwnership != DedicatedAuthMountOwnership ||
		first.Profile.ReviewerSourceMode != "pod-local-rotating-service-account" ||
		first.Profile.Audience != "openbao" || first.Profile.AliasNameSource != "serviceaccount_uid" ||
		!reflect.DeepEqual(first.Profile.Capabilities, []string{"read"}) || first.Profile.BoundIdentityCount != 1 ||
		first.Profile.TokenTTL != "10m" || first.Profile.TokenMaxTTL != "30m" ||
		!first.Profile.TokenNoDefaultPolicy {
		t.Fatalf("report omitted or changed fixed profile facts: %#v", first.Profile)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("Marshal(report) error = %v", err)
	}
	for _, forbidden := range []string{
		"cloudring-consumer-example", "cloudring-openbao-reader",
		"services/cloudring-consumer-example", "capabilities =", "kubernetes.default.svc",
	} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("sanitized report reflected forbidden input or desired state %q", forbidden)
		}
	}
	alternate := validContract()
	alternate.PolicyName = "different-policy"
	alternate.RoleName = "different-role"
	alternate.WorkloadIdentity.Namespace = "different-namespace"
	alternate.WorkloadIdentity.ServiceAccount = "different-service-account"
	alternate.DataPrefix = "different/service-prefix"
	alternateInput, err := json.Marshal(alternate)
	if err != nil {
		t.Fatalf("Marshal(alternate) error = %v", err)
	}
	alternateReport, err := Evaluate(bytes.NewReader(alternateInput))
	if err != nil {
		t.Fatalf("Evaluate(alternate) error = %v", err)
	}
	if !reflect.DeepEqual(first, alternateReport) {
		t.Fatal("sanitized report changes with private contract identifiers")
	}
}

func TestBuildEnforcesExactLeastPrivilegeDesiredState(t *testing.T) {
	contract := validContract()
	plan, problems := Build(contract)
	if len(problems) != 0 {
		t.Fatalf("Build() problems = %#v", problems)
	}
	if plan.AuthMount.Type != "kubernetes" || plan.AuthMount.Description != "CloudRING dedicated Kubernetes workload authentication for cloudring-consumer-example" {
		t.Fatalf("auth mount desired state = %#v", plan.AuthMount)
	}
	if plan.AuthMountOwnership != DedicatedAuthMountOwnership {
		t.Fatalf("auth mount ownership = %q", plan.AuthMountOwnership)
	}
	wantStates := []AuthMountStateRule{
		{PreState: AuthMountAbsent, Decision: AuthMountCreateOwned, Mutates: true, RollbackMode: "disable-current-run-created-mount-after-exact-ownership-readback"},
		{PreState: AuthMountPresentExact, Decision: AuthMountReuseExact, RollbackMode: "none"},
		{PreState: AuthMountPresentConfigAbsent, Decision: AuthMountBlock, RollbackMode: "none"},
		{PreState: AuthMountPresentConfigDrifted, Decision: AuthMountBlock, RollbackMode: "none"},
		{PreState: AuthMountPresentTypeOrDescDrift, Decision: AuthMountBlock, RollbackMode: "none"},
		{PreState: AuthMountUnknownIncompleteUnavailableOrChanged, Decision: AuthMountBlock, RollbackMode: "none"},
	}
	if !reflect.DeepEqual(plan.AuthMountStates, wantStates) {
		t.Fatalf("auth mount state table = %#v", plan.AuthMountStates)
	}
	if plan.AuthConfig.KubernetesHost != "https://kubernetes.default.svc" ||
		plan.AuthConfig.KubernetesCACert != "" || plan.AuthConfig.TokenReviewerJWT != "" ||
		plan.AuthConfig.Issuer != "" || !plan.AuthConfig.DisableISSValidation ||
		plan.AuthConfig.DisableLocalCAJWT || len(plan.AuthConfig.PEMKeys) != 0 {
		t.Fatalf("unsafe local reviewer config: %#v", plan.AuthConfig)
	}
	if plan.AuthConfigReadback.KubernetesHost != plan.AuthConfig.KubernetesHost ||
		plan.AuthConfigReadback.KubernetesCACert != "" || len(plan.AuthConfigReadback.PEMKeys) != 0 ||
		plan.AuthConfigReadback.Issuer != "" || !plan.AuthConfigReadback.DisableISSValidation ||
		plan.AuthConfigReadback.DisableLocalCAJWT || plan.AuthConfigReadback.TokenReviewerJWTSet {
		t.Fatalf("incomplete local reviewer readback: %#v", plan.AuthConfigReadback)
	}
	wantPolicy := "path \"cloudring/data/services/cloudring-consumer-example/*\" {\n  capabilities = [\"read\"]\n}\npath \"auth/token/lookup-self\" {\n  capabilities = [\"read\"]\n}\npath \"auth/token/revoke-self\" {\n  capabilities = [\"update\"]\n}\npath \"sys/capabilities-self\" {\n  capabilities = [\"update\"]\n}\n"
	if plan.ACLPolicy.Policy != wantPolicy || plan.ACLPolicy.CAS != -1 || !plan.ACLPolicy.CASRequired {
		t.Fatalf("ACL policy = %#v", plan.ACLPolicy)
	}
	role := plan.Role
	if !reflect.DeepEqual(role.BoundServiceAccountNames, []string{"cloudring-openbao-reader"}) ||
		!reflect.DeepEqual(role.BoundServiceAccountNamespaces, []string{"cloudring-consumer-example"}) ||
		role.BoundServiceAccountNamespaceSelector != "" || role.Audience != "openbao" ||
		role.AliasNameSource != "serviceaccount_uid" ||
		!reflect.DeepEqual(role.TokenPolicies, []string{"cloudring-consumer-example-kv-read"}) ||
		!role.TokenNoDefaultPolicy || role.TokenTTL != "10m" || role.TokenMaxTTL != "30m" ||
		role.TokenExplicitMaxTTL != "30m" || role.TokenType != "service" ||
		role.TokenNumUses != 0 || role.TokenPeriod != 0 || len(role.TokenBoundCIDRs) != 0 ||
		role.TokenStrictlyBindIP {
		t.Fatalf("role violates exact workload profile: %#v", role)
	}
	if len(plan.Actions) != 16 ||
		findAction(t, plan.Actions, "create-acl-policy-if-absent").CASMode != "create-only-cas-minus-one" ||
		findAction(t, plan.Actions, "create-role-if-absent").CASMode != "api-cas-unavailable-exclusive-lock" ||
		findAction(t, plan.Actions, "readback-kubernetes-auth-role").CASMode != "exact-post-write-readback" {
		t.Fatalf("unexpected action ordering or concurrency contract: %#v", plan.Actions)
	}
	if got := findAction(t, plan.Actions, "initialize-kv-v2-mount-if-absent"); got.RollbackRequired || got.RollbackMode != "retain-current-run-created-empty-mount;automatic-delete-forbidden" || !reflect.DeepEqual(got.DesiredState, plan.KVV2Mount) {
		t.Fatalf("unsafe KV-v2 initialization action: %#v", got)
	}
	if got := findAction(t, plan.Actions, "readback-kv-v2-mount"); got.CASMode != "exact-post-write-readback" || !reflect.DeepEqual(got.DesiredState, plan.KVV2Mount) {
		t.Fatalf("incomplete KV-v2 readback action: %#v", got)
	}
	wantPreStateIDs := []string{"read-auth-mount", "read-kubernetes-auth-config", "list-kubernetes-auth-roles", "read-kv-v2-mount", "read-acl-policy", "read-kubernetes-auth-role"}
	for index, id := range wantPreStateIDs {
		if plan.Actions[index].ID != id || !plan.Actions[index].PreStateRequired || plan.Actions[index].Mutates {
			t.Fatalf("pre-state action %d = %#v, want %q", index, plan.Actions[index], id)
		}
	}
	if plan.Actions[2].FailClosedPrecondition != "preexisting-mount-must-have-no-foreign-roles" {
		t.Fatalf("role inventory pre-state is not fail-closed: %#v", plan.Actions[2])
	}
	if got := findAction(t, plan.Actions, "create-dedicated-auth-mount-if-absent"); got.FailClosedPrecondition != "mount-must-be-absent-or-exact-dedicated-owned-state-with-exact-config" ||
		got.RollbackMode != "disable-only-current-run-created-mount-after-exact-ownership-readback" {
		t.Fatalf("unsafe auth-mount ownership action: %#v", got)
	}
	if got := findAction(t, plan.Actions, "configure-local-reviewer-only-on-created-mount"); got.RunCondition != "create-dedicated-auth-mount-outcome-equals-created-by-current-execution" ||
		got.GlobalMutationGate != authMountLifecycleMutationGate ||
		got.MutationGuard != "auth-mount-created-by-current-run" ||
		got.FailClosedPrecondition != "preexisting-config-must-be-exact;absent-on-preexisting-mount-blocks" ||
		got.RollbackMode != "disable-auth-mount-only-if-created-by-current-execution" {
		t.Fatalf("unsafe auth-config ownership action: %#v", got)
	}
	if got := findAction(t, plan.Actions, "readback-auth-mount"); got.FailClosedPrecondition != "mount-type-and-contract-bound-description-must-match" || !reflect.DeepEqual(got.DesiredState, plan.AuthMount) {
		t.Fatalf("auth-mount ownership readback is incomplete: %#v", got)
	}
	if got := findAction(t, plan.Actions, "readback-kubernetes-auth-config"); got.FailClosedPrecondition != "config-and-token-reviewer-jwt-set-false-must-match-complete-v2-5-5-readback" || !reflect.DeepEqual(got.DesiredState, plan.AuthConfigReadback) {
		t.Fatalf("auth-config readback is incomplete: %#v", got)
	}
	if plan.MutationGate.ID != authMountLifecycleMutationGate ||
		!reflect.DeepEqual(plan.MutationGate.AllowedDecisions, []AuthMountDecision{AuthMountCreateOwned, AuthMountReuseExact}) {
		t.Fatalf("plan mutation gate = %#v", plan.MutationGate)
	}
	for _, action := range plan.Actions {
		if action.Mutates && action.GlobalMutationGate != plan.MutationGate.ID {
			t.Fatalf("mutating action is not bound to lifecycle gate: %#v", action)
		}
	}
}

func TestDecideAuthMountLifecycleFailsClosedForEveryPreState(t *testing.T) {
	tests := []struct {
		state    AuthMountPreState
		decision AuthMountDecision
		mutates  bool
	}{
		{AuthMountAbsent, AuthMountCreateOwned, true},
		{AuthMountPresentExact, AuthMountReuseExact, false},
		{AuthMountPresentConfigAbsent, AuthMountBlock, false},
		{AuthMountPresentConfigDrifted, AuthMountBlock, false},
		{AuthMountPresentTypeOrDescDrift, AuthMountBlock, false},
		{AuthMountUnknownIncompleteUnavailableOrChanged, AuthMountBlock, false},
	}
	for _, test := range tests {
		t.Run(string(test.state), func(t *testing.T) {
			rule, ok := DecideAuthMountLifecycle(test.state)
			if !ok || rule.Decision != test.decision || rule.Mutates != test.mutates {
				t.Fatalf("DecideAuthMountLifecycle(%q) = %#v, %v", test.state, rule, ok)
			}
		})
	}
	plan, problems := Build(validContract())
	if len(problems) != 0 {
		t.Fatalf("Build() problems = %#v", problems)
	}
	for _, test := range tests {
		if test.decision != AuthMountBlock {
			continue
		}
		rule, _ := DecideAuthMountLifecycle(test.state)
		if rule.Mutates || plan.MutationGate.Allows(rule.Decision) {
			t.Fatalf("blocked lifecycle state permits mutation: state=%q rule=%#v gate=%#v", test.state, rule, plan.MutationGate)
		}
		for _, action := range plan.Actions {
			if action.Mutates && action.GlobalMutationGate != plan.MutationGate.ID {
				t.Fatalf("blocked state %q reaches ungated mutation: %#v", test.state, action)
			}
		}
	}
	if plan.MutationGate.Allows(AuthMountDecision("unknown")) || plan.MutationGate.Allows(AuthMountBlock) {
		t.Fatalf("unknown or blocked decision passed mutation gate: %#v", plan.MutationGate)
	}
	if rule, ok := DecideAuthMountLifecycle(AuthMountPreState("unrecognized")); ok || rule != (AuthMountStateRule{}) {
		t.Fatalf("unknown lifecycle state was not rejected: %#v, %v", rule, ok)
	}
}

func TestBuildCannotBypassValidation(t *testing.T) {
	contract := validContract()
	contract.DataPrefix = "services/*"
	plan, problems := Build(contract)
	if len(problems) == 0 || len(plan.Actions) != 0 {
		t.Fatalf("Build() accepted invalid contract: plan=%#v problems=%#v", plan, problems)
	}
}

func TestParseRejectsInvalidProfiles(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Contract)
		path string
		code string
	}{
		{"old v1 schema", func(value *Contract) { value.SchemaVersion = "cloudring.openbao-kubernetes-auth-plan/v1" }, "$.schemaVersion", "unsupported_value"},
		{"reserved auth mount", func(value *Contract) { value.AuthMount = "token" }, "$.authMount", "reserved_name"},
		{"ambiguous auth mount", func(value *Contract) { value.AuthMount = "kubernetes" }, "$.authMount", "shared_mount_name_forbidden"},
		{"missing ownership", func(value *Contract) { value.AuthMountOwnership = "" }, "$.authMountOwnership", "must_equal_dedicated_create_owned"},
		{"shared ownership", func(value *Contract) { value.AuthMountOwnership = "shared" }, "$.authMountOwnership", "must_equal_dedicated_create_owned"},
		{"adopt ownership", func(value *Contract) { value.AuthMountOwnership = "adopt-existing" }, "$.authMountOwnership", "must_equal_dedicated_create_owned"},
		{"invalid kv mount", func(value *Contract) { value.KVV2Mount = "CloudRING" }, "$.kvV2Mount", "invalid_dns_label"},
		{"wildcard prefix", func(value *Contract) { value.DataPrefix = "services/*" }, "$.dataPrefix", "invalid_safe_prefix"},
		{"traversal prefix", func(value *Contract) { value.DataPrefix = "services/../private" }, "$.dataPrefix", "invalid_safe_prefix"},
		{"leading slash", func(value *Contract) { value.DataPrefix = "/services/example" }, "$.dataPrefix", "invalid_safe_prefix"},
		{"policy wildcard", func(value *Contract) { value.PolicyName = "policy-*" }, "$.policyName", "invalid_dns_label"},
		{"default policy", func(value *Contract) { value.PolicyName = "default" }, "$.policyName", "reserved_policy_name"},
		{"root policy", func(value *Contract) { value.PolicyName = "root" }, "$.policyName", "reserved_policy_name"},
		{"response wrapping policy", func(value *Contract) { value.PolicyName = "response-wrapping" }, "$.policyName", "reserved_policy_name"},
		{"role path", func(value *Contract) { value.RoleName = "role/name" }, "$.roleName", "invalid_dns_label"},
		{"namespace wildcard", func(value *Contract) { value.WorkloadIdentity.Namespace = "*" }, "$.workloadIdentity.namespace", "invalid_dns_label"},
		{"service account empty", func(value *Contract) { value.WorkloadIdentity.ServiceAccount = "" }, "$.workloadIdentity.serviceAccount", "invalid_dns_label"},
		{"audience", func(value *Contract) { value.Audience = "vault" }, "$.audience", "must_equal_openbao"},
		{"alias", func(value *Contract) { value.AliasNameSource = "serviceaccount_name" }, "$.aliasNameSource", "must_use_serviceaccount_uid"},
		{"ttl", func(value *Contract) { value.TokenTTL = "1h" }, "$.tokenTTL", "must_equal_cloudring_10m_profile"},
		{"max ttl", func(value *Contract) { value.TokenMaxTTL = "1h" }, "$.tokenMaxTTL", "must_equal_cloudring_30m_profile"},
		{"default policy", func(value *Contract) { value.TokenNoDefaultPolicy = false }, "$.tokenNoDefaultPolicy", "must_be_true"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validContract()
			test.edit(&value)
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			_, problems := Parse(data)
			if !containsProblem(problems, test.path, test.code) {
				t.Fatalf("Parse() problems = %#v, want %s/%s", problems, test.path, test.code)
			}
		})
	}
}

func TestParseRejectsNonCanonicalJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		code  string
	}{
		{"empty", "", "invalid_json"},
		{"malformed", "{", "invalid_json"},
		{"trailing", "{} {}", "invalid_json"},
		{"array", "[]", "invalid_json_contract"},
		{"unknown", `{"credentialMarker":"do-not-reflect"}`, "unknown_field"},
		{"duplicate", `{"schemaVersion":"one","schemaVersion":"two"}`, "duplicate_field"},
		{"nested duplicate", `{"workloadIdentity":{"namespace":"one","namespace":"two"}}`, "duplicate_field"},
		{"nested unknown", `{"workloadIdentity":{"credentialMarker":"do-not-reflect"}}`, "unknown_field"},
		{"wrong field type", `{"tokenNoDefaultPolicy":"true"}`, "invalid_json_contract"},
		{"excess nesting", strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34), "invalid_json_contract"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, problems := Parse([]byte(test.input))
			if len(problems) == 0 || problems[0].Code != test.code {
				t.Fatalf("Parse() problems = %#v, want code %q", problems, test.code)
			}
		})
	}
}

func TestEvaluateDoesNotReflectRejectedMaterial(t *testing.T) {
	marker := "credential-marker-do-not-reflect"
	contract := validContract()
	contract.Audience = marker
	input, err := json.Marshal(contract)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	report, err := Evaluate(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal(report) error = %v", err)
	}
	if report.Status != "blocked" || bytes.Contains(encoded, []byte(marker)) {
		t.Fatalf("blocked report reflected input: %s", encoded)
	}
}

func TestEvaluateBoundsInputAndSanitizesReadErrors(t *testing.T) {
	report, err := Evaluate(strings.NewReader(strings.Repeat("x", MaxInputBytes+1)))
	if err != nil || report.Status != "blocked" ||
		!containsProblem(report.Blockers, "$", "input_too_large") {
		t.Fatalf("oversized Evaluate() report=%#v err=%v", report, err)
	}
	if _, err := Evaluate(errorReader{}); !errors.Is(err, errInputUnavailable) {
		t.Fatalf("Evaluate(errorReader) error = %v", err)
	}
}

func validContract() Contract {
	return Contract{
		SchemaVersion: SchemaVersion, AuthMount: "kubernetes-consumer-example", AuthMountOwnership: DedicatedAuthMountOwnership, KVV2Mount: "cloudring",
		DataPrefix: "services/cloudring-consumer-example", PolicyName: "cloudring-consumer-example-kv-read",
		RoleName:         "cloudring-consumer-example",
		WorkloadIdentity: WorkloadIdentity{Namespace: "cloudring-consumer-example", ServiceAccount: "cloudring-openbao-reader"},
		Audience:         "openbao", AliasNameSource: "serviceaccount_uid", TokenTTL: "10m", TokenMaxTTL: "30m",
		TokenNoDefaultPolicy: true,
	}
}

func validJSON(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(validContract())
	if err != nil {
		t.Fatalf("Marshal(valid contract) error = %v", err)
	}
	return data
}

func containsProblem(problems []Problem, path, code string) bool {
	for _, problem := range problems {
		if problem.Path == path && problem.Code == code {
			return true
		}
	}
	return false
}

func findAction(t *testing.T, actions []Action, id string) Action {
	t.Helper()
	for _, action := range actions {
		if action.ID == id {
			return action
		}
	}
	t.Fatalf("action %q not found", id)
	return Action{}
}

func findActionSummary(t *testing.T, actions []ActionSummary, id string) ActionSummary {
	t.Helper()
	for _, action := range actions {
		if action.ID == id {
			return action
		}
	}
	t.Fatalf("action summary %q not found", id)
	return ActionSummary{}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
