// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package openbaoexecutor

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/openbaoauth"
)

func TestSyntheticProfileMatchesCanonicalManifest(t *testing.T) {
	profile := syntheticProfile(t)
	rendered, err := Render(profile)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	want, err := os.ReadFile("../../deploy/kubernetes/secret-manager/consumer-example/bootstrap-executor.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendered, want) {
		t.Fatalf("canonical manifest drifted\n--- rendered ---\n%s\n--- tracked ---\n%s", rendered, want)
	}
	if strings.Count(string(rendered), "\n---\n") != 9 {
		t.Fatalf("rendered document separators = %d, want 9", strings.Count(string(rendered), "\n---\n"))
	}
	for _, forbidden := range []string{"kind: Secret\n", "kind: Pod\n", "kind: Job\n"} {
		if strings.Contains(string(rendered), forbidden) {
			t.Fatalf("rendered forbidden capability %q", forbidden)
		}
	}
}

func TestValidateRejectsInconsistentIdentityProfiles(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Profile)
		path string
		code string
	}{
		{"schema", func(p *Profile) { p.SchemaVersion = "v2" }, "$.schemaVersion", "unsupported_value"},
		{"shared mount", func(p *Profile) { p.Contract.AuthMount = "kubernetes" }, "$.contract.authMount", "shared_mount_name_forbidden"},
		{"executor namespace", func(p *Profile) { p.ExecutorIdentity.Namespace = "other" }, "$.executorIdentity.namespace", "must_equal_workload_namespace"},
		{"executor equals workload", func(p *Profile) { p.ExecutorIdentity.ServiceAccount = p.Contract.WorkloadIdentity.ServiceAccount }, "$.executorIdentity.serviceAccount", "must_differ_from_workload_identity"},
		{"lease namespace", func(p *Profile) { p.Lease.Namespace = "other" }, "$.lease.namespace", "must_equal_executor_namespace"},
		{"lease scope", func(p *Profile) { p.Lease.Name = "other" }, "$.lease.name", "must_equal_executor_identity_scope"},
		{"wrong service account namespace", func(p *Profile) { p.NegativeIdentities.WrongServiceAccount.Namespace = "other" }, "$.negativeIdentities.wrongServiceAccount.namespace", "must_equal_workload_namespace"},
		{"wrong service account equals workload", func(p *Profile) {
			p.NegativeIdentities.WrongServiceAccount.ServiceAccount = p.Contract.WorkloadIdentity.ServiceAccount
		}, "$.negativeIdentities.wrongServiceAccount.serviceAccount", "must_be_distinct"},
		{"wrong namespace is workload namespace", func(p *Profile) {
			p.NegativeIdentities.WrongNamespace.Namespace = p.Contract.WorkloadIdentity.Namespace
		}, "$.negativeIdentities.wrongNamespace.namespace", "must_differ_from_workload_namespace"},
		{"wrong namespace changes service account", func(p *Profile) { p.NegativeIdentities.WrongNamespace.ServiceAccount = "other" }, "$.negativeIdentities.wrongNamespace.serviceAccount", "must_equal_workload_service_account"},
		{"unsafe lease name", func(p *Profile) { p.Lease.Name = "unsafe/name" }, "$.lease.name", "invalid_dns_label"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := syntheticProfile(t)
			test.edit(&profile)
			problems := Validate(profile)
			if !hasProblem(problems, test.path, test.code) {
				t.Fatalf("Validate() problems = %#v, want %s/%s", problems, test.path, test.code)
			}
			if _, err := Render(profile); !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("Render() error = %v, want ErrInvalidProfile", err)
			}
		})
	}
}

func TestDecodeRejectsAmbiguousOrUnboundedInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		code  string
	}{
		{"empty", "", "invalid_json"},
		{"unknown", `{"schemaVersion":"cloudring.openbao-kubernetes-auth-executor/v1","unexpected":true}`, "unknown_field"},
		{"duplicate", `{"schemaVersion":"one","schemaVersion":"two"}`, "duplicate_field"},
		{"nested duplicate", `{"contract":{"authMount":"one","authMount":"two"}}`, "duplicate_field"},
		{"case-folded alias", `{"schemaVersion":"cloudring.openbao-kubernetes-auth-executor/v1","SchemaVersion":"cloudring.openbao-kubernetes-auth-executor/v1"}`, "unknown_field"},
		{"trailing", `{} {}`, "invalid_json"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, problems, err := Decode(strings.NewReader(test.input))
			if err != nil || !hasProblemCode(problems, test.code) {
				t.Fatalf("Decode() problems=%#v err=%v, want code %s", problems, err, test.code)
			}
		})
	}
	_, problems, err := Decode(strings.NewReader(strings.Repeat("x", MaxInputBytes+1)))
	if err != nil || !hasProblemCode(problems, "input_too_large") {
		t.Fatalf("oversized Decode() problems=%#v err=%v", problems, err)
	}
	if _, _, err := Decode(executorErrorReader{}); !errors.Is(err, errInputUnavailable) {
		t.Fatalf("Decode(errorReader) error = %v", err)
	}
}

func TestVerifyRenderedRejectsAnyManifestMutation(t *testing.T) {
	profile := syntheticProfile(t)
	rendered, err := Render(profile)
	if err != nil {
		t.Fatal(err)
	}
	mutated := bytes.Replace(rendered, []byte("      - update"), []byte("      - update\n      - create"), 1)
	if err := VerifyRendered(profile, mutated); !errors.Is(err, ErrRenderedManifestDrift) {
		t.Fatalf("VerifyRendered() error = %v", err)
	}
	if err := VerifyRendered(profile, rendered); err != nil {
		t.Fatalf("VerifyRendered(canonical) error = %v", err)
	}
}

func TestSemanticVerifierIndependentlyRejectsPrivilegeAndOwnershipDrift(t *testing.T) {
	profile := syntheticProfile(t)
	rendered, err := Render(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRenderedSemantics(profile, rendered); err != nil {
		t.Fatalf("verifyRenderedSemantics(canonical) error = %v", err)
	}
	tests := []struct {
		name        string
		old         string
		replacement string
	}{
		{
			name:        "widened verb",
			old:         "      - update\n",
			replacement: "      - update\n      - create\n",
		},
		{
			name:        "preclaimed lease",
			old:         "spec: {}\n",
			replacement: "spec:\n  holderIdentity: 'stale-holder'\n",
		},
		{
			name:        "wrong binding subject",
			old:         "    name: 'cloudring-openbao-bootstrap-executor'\n    namespace: 'cloudring-consumer-example'\n",
			replacement: "    name: 'cloudring-openbao-reader-denied'\n    namespace: 'cloudring-consumer-example'\n",
		},
		{
			name:        "automounted executor token",
			old:         "automountServiceAccountToken: false\n",
			replacement: "automountServiceAccountToken: true\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := bytes.Replace(rendered, []byte(test.old), []byte(test.replacement), 1)
			if bytes.Equal(mutated, rendered) {
				t.Fatal("test mutation anchor is absent")
			}
			if err := verifyRenderedSemantics(profile, mutated); !errors.Is(err, ErrRenderedManifestDrift) {
				t.Fatalf("verifyRenderedSemantics() error = %v, want ErrRenderedManifestDrift", err)
			}
		})
	}
}

func TestRenderQuotesYAMLKeywordDNSLabels(t *testing.T) {
	profile := syntheticProfile(t)
	profile.NegativeIdentities.WrongNamespace.Namespace = "null"
	rendered, err := Render(profile)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if !bytes.Contains(rendered, []byte("namespace: 'null'")) {
		t.Fatalf("rendered manifest does not quote YAML keyword DNS label")
	}
	if err := verifyRenderedSemantics(profile, rendered); err != nil {
		t.Fatalf("verifyRenderedSemantics() error = %v", err)
	}
}

func TestExecutorScopeNameSeparatesHyphenAmbiguity(t *testing.T) {
	left := openbaoauth.WorkloadIdentity{Namespace: "a-b", ServiceAccount: "c"}
	right := openbaoauth.WorkloadIdentity{Namespace: "a", ServiceAccount: "b-c"}
	leftName := ExecutorScopeName(left)
	rightName := ExecutorScopeName(right)
	if leftName == rightName {
		t.Fatalf("ambiguous executor identities share scope %q", leftName)
	}
	for _, name := range []string{leftName, rightName} {
		if len(name) != 63 || !dnsLabel.MatchString(name) {
			t.Fatalf("ExecutorScopeName() = %q, want exact 63-byte DNS label", name)
		}
	}
	for index, identity := range []openbaoauth.WorkloadIdentity{left, right} {
		profile := syntheticProfile(t)
		profile.Contract.WorkloadIdentity.Namespace = identity.Namespace
		profile.ExecutorIdentity = identity
		profile.Lease = LeaseTarget{Namespace: identity.Namespace, Name: ExecutorScopeName(identity)}
		profile.NegativeIdentities.WrongServiceAccount.Namespace = identity.Namespace
		profile.NegativeIdentities.WrongNamespace.Namespace = []string{"left-negative", "right-negative"}[index]
		if problems := Validate(profile); len(problems) != 0 {
			t.Fatalf("Validate(profile %d) problems = %#v", index, problems)
		}
		if _, err := Render(profile); err != nil {
			t.Fatalf("Render(profile %d) error = %v", index, err)
		}
	}
}

func syntheticProfile(t *testing.T) Profile {
	t.Helper()
	data, err := os.ReadFile("../../contracts/openbao-kubernetes-auth/fixtures/synthetic-kubernetes-auth-executor.json")
	if err != nil {
		t.Fatal(err)
	}
	profile, problems := Parse(data)
	if len(problems) != 0 {
		t.Fatalf("Parse() problems = %#v", problems)
	}
	return profile
}

func hasProblem(problems []Problem, path, code string) bool {
	for _, problem := range problems {
		if problem.Path == path && problem.Code == code {
			return true
		}
	}
	return false
}

func hasProblemCode(problems []Problem, code string) bool {
	for _, problem := range problems {
		if problem.Code == code {
			return true
		}
	}
	return false
}

type executorErrorReader struct{}

func (executorErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("sensitive input detail")
}
