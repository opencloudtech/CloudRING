// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package roadmapprogram

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestShippedRoadmap(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..", "roadmap")
	if err := ValidateDir(root); err != nil {
		t.Fatalf("validate shipped roadmap: %v", err)
	}
}

func TestParseRejectsUnsafeYAML(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{name: "malformed", doc: "spec: [", want: "parse roadmap YAML"},
		{name: "unknown field", doc: "apiVersion: roadmap.cloudring.org/v1alpha1\nkind: DeliveryRoadmap\nunknown: true\n", want: "field unknown not found"},
		{name: "duplicate key", doc: "kind: DeliveryRoadmap\nkind: DeliveryRoadmap\n", want: "duplicate YAML mapping key"},
		{name: "alias", doc: "kind: &kind DeliveryRoadmap\nmetadata: {name: *kind}\n", want: "YAML aliases are not allowed"},
		{name: "trailing document", doc: "kind: DeliveryRoadmap\n---\nkind: DeliveryRoadmap\n", want: "unexpected trailing document"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(test.doc))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Parse() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateRejectsInvalidGraphAndContracts(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(string) string
		prepare func(*testing.T, *os.Root)
		want    string
	}{
		{
			name: "missing canonical dependency",
			mutate: func(document string) string {
				return strings.Replace(document, "dependsOn: [G23] # G24", "dependsOn: [G22] # G24", 1)
			},
			want: "G24: dependsOn must be exactly [G23]",
		},
		{
			name: "dependency cycle",
			mutate: func(document string) string {
				return strings.Replace(document, "dependsOn: [] # G00", "dependsOn: [G27] # G00", 1)
			},
			want: "dependency cycle detected",
		},
		{
			name: "invalid status",
			mutate: func(document string) string {
				return strings.Replace(document, "status: not_started", "status: almost_done", 1)
			},
			want: `invalid status "almost_done"`,
		},
		{
			name: "G27 boundary",
			mutate: func(document string) string {
				return strings.Replace(document, "dependsOn: [G24] # G27", "dependsOn: [G25] # G27", 1)
			},
			want: "G27: dependsOn must be exactly [G24]",
		},
		{
			name: "post 1.0 track",
			mutate: func(document string) string {
				return strings.Replace(document, "releaseTrack: post_1_0 # G25", "releaseTrack: cloudring_1_0 # G25", 1)
			},
			want: "G25: releaseTrack must be post_1_0",
		},
		{
			name: "missing hub",
			mutate: func(document string) string {
				return strings.Replace(document, "defaultDeploymentTargets: [public_clean_room, hub]", "defaultDeploymentTargets: [public_clean_room]", 1)
			},
			want: "default deployment targets must include hub",
		},
		{
			name: "missing release target",
			mutate: func(document string) string {
				return strings.Replace(document, "deploymentTargets: [public_clean_room, hub, independent_provider] # G27", "deploymentTargets: [public_clean_room, hub] # G27", 1)
			},
			want: "G27: deployment targets must include independent_provider",
		},
		{
			name: "missing invariant",
			mutate: func(document string) string {
				return strings.Replace(document, "    - protected_main_only\n", "", 1)
			},
			want: "missing required invariant: protected_main_only",
		},
		{
			name: "missing contract file",
			mutate: func(document string) string {
				return strings.Replace(document, "verificationMatrix: VERIFICATION_MATRIX.md", "verificationMatrix: missing.md", 1)
			},
			want: "verificationMatrix: file reference must identify",
		},
		{
			name: "goal path escape",
			mutate: func(document string) string {
				return strings.Replace(document, "file: goals/G00.md", "file: ../outside.md", 1)
			},
			want: "cannot read goal file",
		},
		{
			name: "goal symlink escape",
			prepare: func(t *testing.T, root *os.Root) {
				t.Helper()
				if err := root.Remove("goals/G00.md"); err != nil {
					t.Fatal(err)
				}
				if err := root.Symlink("../EXECUTION_CONTRACT.md", "goals/G00.md"); err != nil {
					t.Fatal(err)
				}
			},
			want: "cannot read goal file",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, repository, document := writeFixture(t)
			defer repository.Close()
			if test.mutate != nil {
				document = test.mutate(document)
			}
			writeFile(t, repository, "roadmap.yaml", document)
			if test.prepare != nil {
				test.prepare(t, repository)
			}
			err := ValidateDir(root)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateDir() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateRejectsInvalidRequirementIDs(t *testing.T) {
	tests := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{name: "missing", old: "requirementIds: [CR-G00-DELIVERY]", new: "requirementIds: []", want: "G00: requirementIds must not be empty"},
		{name: "duplicate within goal", old: "requirementIds: [CR-G00-DELIVERY]", new: "requirementIds: [CR-G00-DELIVERY, CR-G00-DELIVERY]", want: "G00: duplicate requirement ids: CR-G00-DELIVERY"},
		{name: "malformed", old: "CR-G00-DELIVERY", new: "not-a-requirement", want: `G00: invalid requirement id "not-a-requirement"`},
		{name: "wrong goal", old: "CR-G00-DELIVERY", new: "CR-G01-DELIVERY", want: `G00: invalid requirement id "CR-G01-DELIVERY"`},
		{name: "duplicate across goals", old: "CR-G01-DELIVERY", new: "CR-G00-DELIVERY", want: "requirement id CR-G00-DELIVERY is shared by G00 and G01"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, repository, document := writeFixture(t)
			defer repository.Close()
			writeFile(t, repository, "roadmap.yaml", strings.Replace(document, test.old, test.new, 1))
			err := ValidateDir(root)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateDir() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateRejectsHeadingAndUnsafeStatus(t *testing.T) {
	root, repository, document := writeFixture(t)
	defer repository.Close()
	writeFile(t, repository, "roadmap.yaml", strings.Replace(document, "status: not_started # G01", "status: in_progress # G01", 1))
	writeFile(t, repository, "goals/G00.md", "# G99 — Wrong goal\n")

	err := ValidateDir(root)
	if err == nil || !strings.Contains(err.Error(), "G00: goal file heading must start with G00") ||
		!strings.Contains(err.Error(), "G01: in_progress status requires delivered dependency G00") {
		t.Fatalf("ValidateDir() error = %v, want heading and dependency-state blockers", err)
	}
}

func TestValidateGoalRequirementReferences(t *testing.T) {
	t.Run("declared canonical reference", func(t *testing.T) {
		root, repository, document := writeFixture(t)
		defer repository.Close()
		document = strings.Replace(document, "CR-G05-DELIVERY", "CR-G05-IAM", 1)
		writeFile(t, repository, "roadmap.yaml", document)
		writeFile(t, repository, "goals/G05.md", "# G05 — Goal\n\nMeets CR-G05-IAM.\n")
		if err := ValidateDir(root); err != nil {
			t.Fatalf("ValidateDir() error = %v", err)
		}
	})

	t.Run("dangling legacy-like reference", func(t *testing.T) {
		root, repository, document := writeFixture(t)
		defer repository.Close()
		writeFile(t, repository, "roadmap.yaml", document)
		writeFile(t, repository, "goals/G05.md", "# G05 — Goal\n\nClaims CR-FND-220.\n")
		err := ValidateDir(root)
		if err == nil || !strings.Contains(err.Error(), "G05: goal file references undeclared requirement CR-FND-220") {
			t.Fatalf("ValidateDir() error = %v, want dangling-reference blocker", err)
		}
	})
}

func TestCanTransitionEnforcesStateMachineAndDependencies(t *testing.T) {
	root, repository, document := writeFixture(t)
	defer repository.Close()
	writeFile(t, repository, "roadmap.yaml", document)
	roadmap, err := Load(root)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if err := roadmap.CanTransition("G01", StatusInProgress); err == nil || !strings.Contains(err.Error(), "G00") {
		t.Fatalf("G01 should wait for G00, got %v", err)
	}
	roadmap.Spec.DeliveryOrder[0].Status = StatusInProgress
	if err := roadmap.CanTransition("G00", StatusDelivered); err != nil {
		t.Fatalf("G00 should transition from in_progress to delivered: %v", err)
	}
	roadmap.Spec.DeliveryOrder[0].Status = StatusDelivered
	if err := roadmap.CanTransition("G01", StatusInProgress); err != nil {
		t.Fatalf("G01 should start after G00: %v", err)
	}
	if err := roadmap.CanTransition("G01", StatusDelivered); err == nil || !strings.Contains(err.Error(), "cannot transition from not_started") {
		t.Fatalf("direct delivery should be rejected, got %v", err)
	}
	if err := roadmap.CanTransition("G00", StatusBlocked); err == nil || !strings.Contains(err.Error(), "cannot transition from delivered") {
		t.Fatalf("delivered goal must be terminal, got %v", err)
	}
}

func writeFixture(t *testing.T) (string, *os.Root, string) {
	t.Helper()
	root := t.TempDir()
	repository, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.MkdirAll("goals", 0o755); err != nil {
		if closeErr := repository.Close(); closeErr != nil {
			t.Fatalf("create fixture goals: %v; close fixture root: %v", err, closeErr)
		}
		t.Fatal(err)
	}

	for _, name := range []string{
		"EXECUTION_CONTRACT.md", "TARGET_ARCHITECTURE.md", "CURRENT_STATE.md", "ISSUE_MAP.md",
		"LEGACY_WORK_MAP.md", "HUB_PREREQUISITES.md", "MEASUREMENT_CONTRACT.md", "EVIDENCE_POLICY.md",
		"VERIFICATION_MATRIX.md", "COVERAGE.md",
	} {
		writeFile(t, repository, name, "# Contract\n")
	}
	copyShippedRoadmapFile(t, repository, "state.schema.json")
	copyShippedRoadmapFile(t, repository, "evidence.schema.json")

	var goals strings.Builder
	for _, id := range requiredGoalOrder {
		writeFile(t, repository, "goals/"+id+".md", "# "+id+" — Goal\n")
		dependency := "[]"
		switch id {
		case "G00":
		case "G27", "G25", "G26":
			if id == "G27" {
				dependency = "[G24]"
			} else {
				dependency = "[G27]"
			}
		default:
			var number int
			if _, err := fmt.Sscanf(id, "G%02d", &number); err != nil {
				if closeErr := repository.Close(); closeErr != nil {
					t.Fatalf("parse fixture goal id: %v; close fixture root: %v", err, closeErr)
				}
				t.Fatal(err)
			}
			dependency = fmt.Sprintf("[G%02d]", number-1)
		}
		releaseTrack := ""
		if id == "G25" || id == "G26" {
			releaseTrack = "      releaseTrack: post_1_0 # " + id + "\n"
		}
		targets := ""
		switch id {
		case "G24", "G27":
			targets = "      deploymentTargets: [public_clean_room, hub, independent_provider] # " + id + "\n"
		case "G25":
			targets = "      deploymentTargets: [public_clean_room, hub, independent_provider, region_primary, region_secondary] # G25\n"
		case "G26":
			targets = "      deploymentTargets: [public_clean_room, hub, independent_provider, federation_provider_a, federation_provider_b] # G26\n"
		}
		fmt.Fprintf(&goals, "    - id: %s\n      file: goals/%s.md\n      dependsOn: %s # %s\n      requirementIds: [CR-%s-DELIVERY]\n      status: not_started # %s\n%s      liveDeployment: required\n%s", id, id, dependency, id, id, id, releaseTrack, targets)
	}

	document := `apiVersion: roadmap.cloudring.org/v1alpha1
kind: DeliveryRoadmap
metadata:
  name: test
spec:
  executionContract: EXECUTION_CONTRACT.md
  targetArchitecture: TARGET_ARCHITECTURE.md
  currentState: CURRENT_STATE.md
  issueMap: ISSUE_MAP.md
  legacyWorkMap: LEGACY_WORK_MAP.md
  hubPrerequisites: HUB_PREREQUISITES.md
  measurementContract: MEASUREMENT_CONTRACT.md
  evidencePolicy: EVIDENCE_POLICY.md
  verificationMatrix: VERIFICATION_MATRIX.md
  stateSchema: state.schema.json
  evidenceSchema: evidence.schema.json
  defaultDeploymentTargets: [public_clean_room, hub]
  deliveryOrder:
` + goals.String() + `  invariant:
    - complete_in_dependency_order
    - reusable_implementation_is_oss
    - public_clean_room_proof_precedes_downstreams
    - protected_main_only
    - exact_downstream_pins
    - every_provider_pin_passes_safepush_stage_9
    - deploy_every_goal_to_hub_cloudring_org
    - cumulative_live_regression_every_goal
    - signed_prerelease_sbom_and_provenance_every_goal
    - no_scaffold_or_fixture_readiness_claims
    - final_broad_security_review_on_1_0_path_is_G27
    - every_post_1_0_track_requires_terminal_security_review
    - cloudring_1_0_does_not_depend_on_multi_region_or_federation
    - federation_is_opt_in_and_never_a_standalone_provider_dependency
`
	return root, repository, document
}

func writeFile(t *testing.T, root *os.Root, path, content string) {
	t.Helper()
	if err := root.WriteFile(filepath.FromSlash(path), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func copyShippedRoadmapFile(t *testing.T, root *os.Root, name string) {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// #nosec G304 -- the caller supplies a fixed fixture name and the source is
	// anchored to this test file's checked-in roadmap directory.
	data, err := os.ReadFile(filepath.Join(filepath.Dir(testFile), "..", "..", "roadmap", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(name, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
