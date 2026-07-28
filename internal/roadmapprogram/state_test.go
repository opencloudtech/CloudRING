// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package roadmapprogram

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestValidateCompilesStrictSemanticSchemas(t *testing.T) {
	tests := []struct {
		name       string
		schemaFile string
		mutate     func(string) string
		want       string
	}{
		{
			name:       "duplicate state schema key",
			schemaFile: "state.schema.json",
			mutate: func(schema string) string {
				return strings.Replace(schema, "{", "{\n  \"type\": \"object\",", 1)
			},
			want: "duplicate JSON object key",
		},
		{
			name:       "evidence schema missing semantic shape",
			schemaFile: "evidence.schema.json",
			mutate:     func(string) string { return `{}` },
			want:       "must declare draft 2020-12",
		},
		{
			name:       "state schema does not compile",
			schemaFile: "state.schema.json",
			mutate: func(schema string) string {
				return strings.Replace(schema, `"$ref": "#/$defs/digest"`, `"$ref": "#/$defs/missing"`, 1)
			},
			want: "compile JSON Schema",
		},
		{
			name:       "external schema reference",
			schemaFile: "evidence.schema.json",
			mutate: func(schema string) string {
				return strings.Replace(schema, `"$ref": "#/$defs/digest"`, `"$ref": "https://private.invalid/schema.json"`, 1)
			},
			want: "references must be local fragments",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, repository, document := writeFixture(t)
			defer repository.Close()
			writeFile(t, repository, "roadmap.yaml", document)
			schema := readShippedRoadmapFile(t, test.schemaFile)
			writeFile(t, repository, test.schemaFile, test.mutate(schema))
			err := ValidateDir(root)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateDir() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestShippedSchemaExamplesValidate(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root, err := openRoadmapRoot(filepath.Join(filepath.Dir(file), "..", "..", "roadmap"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	tests := []struct {
		name       string
		schemaFile string
		shape      schemaShape
		example    string
	}{
		{name: "state", schemaFile: "state.schema.json", shape: stateSchemaShape, example: "examples/delivered-state.example.json"},
		{name: "evidence", schemaFile: "evidence.schema.json", shape: evidenceSchemaShape, example: "examples/measurement-evidence.example.json"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schema, err := compileRoadmapSchema(root, test.schemaFile, test.shape)
			if err != nil {
				t.Fatalf("compileRoadmapSchema() error = %v", err)
			}
			data, err := readRegular(root, test.example)
			if err != nil {
				t.Fatal(err)
			}
			document, err := decodeStrictJSON(data)
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(document); err != nil {
				t.Fatalf("schema.Validate() error = %v", err)
			}
		})
	}
}

func TestValidateRequiresStateForActiveStatuses(t *testing.T) {
	for _, status := range []Status{StatusInProgress, StatusBlocked, StatusDelivered} {
		t.Run(string(status), func(t *testing.T) {
			root, repository, document := writeFixture(t)
			defer repository.Close()
			document = strings.Replace(document, "status: not_started # G00", "status: "+string(status)+" # G00", 1)
			writeFile(t, repository, "roadmap.yaml", document)
			err := ValidateDir(root)
			want := "G00: " + string(status) + " status requires state/G00.json"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("ValidateDir() error = %v, want substring %q", err, want)
			}
		})
	}
}

func TestValidateRejectsDeliveredStateWithUnresolvedPlaceholderEvidence(t *testing.T) {
	root, repository, document := deliveredG00Fixture(t)
	defer repository.Close()
	writeFile(t, repository, "roadmap.yaml", document)
	err := ValidateDir(root)
	if err == nil || !strings.Contains(err.Error(), "evidence is unresolved") {
		t.Fatalf("ValidateDir() error = %v, want unresolved-evidence blocker", err)
	}
}

func TestValidateAcceptsDeliveredStateWithExactResolvedEvidence(t *testing.T) {
	root, repository, document, resolver := resolvedDeliveredG00Fixture(t)
	defer repository.Close()
	writeFile(t, repository, "roadmap.yaml", document)
	if err := ValidateDirWithOptions(root, validationOptions(resolver)); err != nil {
		t.Fatalf("ValidateDirWithOptions() error = %v", err)
	}
}

func TestValidateRejectsInvalidResolvedEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *os.Root, memoryResolver)
		want   string
	}{
		{
			name: "digest mismatch",
			mutate: func(_ *testing.T, _ *os.Root, resolver memoryResolver) {
				resolved := resolver[requirementEvidenceLocator]
				resolved.Payload = append(resolved.Payload, ' ')
				resolver[requirementEvidenceLocator] = resolved
			},
			want: "evidence digest mismatch",
		},
		{
			name: "schema mismatch",
			mutate: func(t *testing.T, repository *os.Root, resolver memoryResolver) {
				replaceResolvedPayload(t, repository, resolver, requirementEvidenceLocator, []byte(`{}`))
			},
			want: "does not satisfy evidence schema",
		},
		{
			name: "expired record",
			mutate: func(t *testing.T, repository *os.Root, resolver memoryResolver) {
				record := decodeJSONObject(t, resolver[requirementEvidenceLocator].Payload)
				record["expiresAt"] = "2026-07-22T12:00:00Z"
				replaceResolvedPayload(t, repository, resolver, requirementEvidenceLocator, marshalJSON(t, record))
			},
			want: "evidence record has expired",
		},
		{
			name: "tuple mismatch",
			mutate: func(t *testing.T, repository *os.Root, resolver memoryResolver) {
				record := decodeJSONObject(t, resolver[requirementEvidenceLocator].Payload)
				record["requirement"] = "CR-G00-OTHER"
				replaceResolvedPayload(t, repository, resolver, requirementEvidenceLocator, marshalJSON(t, record))
			},
			want: "evidence requirement tuple mismatch",
		},
		{
			name: "untrusted attestation",
			mutate: func(_ *testing.T, _ *os.Root, resolver memoryResolver) {
				resolved := resolver[attestationLocator]
				resolved.Trusted = false
				resolver[attestationLocator] = resolved
			},
			want: "attestation trust policy did not pass",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, repository, document, resolver := resolvedDeliveredG00Fixture(t)
			defer repository.Close()
			writeFile(t, repository, "roadmap.yaml", document)
			test.mutate(t, repository, resolver)
			err := ValidateDirWithOptions(root, validationOptions(resolver))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateDirWithOptions() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateBindsDeploymentEvidenceToExactState(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any, memoryResolver)
		want   string
	}{
		{
			name: "target",
			mutate: func(record map[string]any, _ memoryResolver) {
				record["environment"].(map[string]any)["class"] = "hub"
			},
			want: "evidence environment tuple mismatch",
		},
		{
			name: "fingerprint",
			mutate: func(record map[string]any, _ memoryResolver) {
				record["environment"].(map[string]any)["fingerprint"] = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
			},
			want: "evidence environment fingerprint mismatch",
		},
		{
			name: "profile",
			mutate: func(record map[string]any, resolver memoryResolver) {
				record["environment"].(map[string]any)["profile"] = referenceForResolverObject(
					resolver,
					"protected://test/profile/hub",
				)
			},
			want: "evidence environment profile mismatch",
		},
		{
			name: "GitOps revision",
			mutate: func(record map[string]any, _ memoryResolver) {
				record["environment"].(map[string]any)["gitOpsRevision"] = "cccccccccccccccccccccccccccccccccccccccc"
			},
			want: "evidence GitOps tuple mismatch",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, repository, document, resolver := resolvedDeliveredG00Fixture(t)
			defer repository.Close()
			writeFile(t, repository, "roadmap.yaml", document)
			record := decodeJSONObject(t, resolver["protected://test/evidence/public"].Payload)
			test.mutate(record, resolver)
			replaceResolvedPayload(t, repository, resolver, "protected://test/evidence/public", marshalJSON(t, record))
			err := ValidateDirWithOptions(root, validationOptions(resolver))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateDirWithOptions() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestDeliveredStateRejectsReusedIndependentEnvironmentFingerprint(t *testing.T) {
	sharedEvidence := evidenceReference{
		Digest:         "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Locator:        "protected://test/evidence/shared-environment",
		RetentionUntil: "2035-01-01T00:00:00Z",
	}
	sharedFingerprint := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tests := []struct {
		goalID string
		left   string
		right  string
	}{
		{goalID: "G25", left: "region_primary", right: "region_secondary"},
		{goalID: "G26", left: "federation_provider_a", right: "federation_provider_b"},
	}
	for _, test := range tests {
		t.Run(test.goalID, func(t *testing.T) {
			deployments := []deploymentProof{
				{
					Target:                 test.left,
					EnvironmentFingerprint: sharedFingerprint,
					Evidence:               []evidenceReference{sharedEvidence},
				},
				{
					Target:                 test.right,
					EnvironmentFingerprint: sharedFingerprint,
					Evidence:               []evidenceReference{sharedEvidence},
				},
			}
			blockers := validateIndependentDeploymentFingerprints(test.goalID, deployments)
			want := test.left + " and " + test.right + " must use distinct environment fingerprints"
			if got := strings.Join(blockers, "\n"); !strings.Contains(got, want) {
				t.Fatalf("blockers = %q, want substring %q", got, want)
			}
		})
	}
}

func TestDeliveredStateRejectsEmptyIndependentEnvironmentFingerprint(t *testing.T) {
	deployments := []deploymentProof{
		{Target: "region_primary", EnvironmentFingerprint: ""},
		{Target: "region_secondary", EnvironmentFingerprint: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
	}
	blockers := validateIndependentDeploymentFingerprints("G25", deployments)
	if got := strings.Join(blockers, "\n"); !strings.Contains(got, "require non-empty environment fingerprints") {
		t.Fatalf("blockers = %q, want non-empty-fingerprint blocker", got)
	}
}

func TestValidateRequiresVerifierFreshnessPolicy(t *testing.T) {
	tests := []struct {
		name    string
		ceiling time.Duration
		present bool
		want    string
	}{
		{name: "missing", want: "verifier freshness ceiling is required"},
		{name: "nonpositive", ceiling: 0, present: true, want: "outside the allowed range"},
		{name: "too broad", ceiling: maxGoalEvidenceFreshness + time.Second, present: true, want: "outside the allowed range"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, repository, document, resolver := resolvedDeliveredG00Fixture(t)
			defer repository.Close()
			writeFile(t, repository, "roadmap.yaml", document)
			options := ValidationOptions{
				EvidenceResolver: resolver,
				CurrentTime:      time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC),
			}
			if test.present {
				options.FreshnessCeilings = map[string]time.Duration{"G00": test.ceiling}
			}
			err := ValidateDirWithOptions(root, options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateDirWithOptions() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateRejectsEvidenceOlderThanVerifierCeiling(t *testing.T) {
	root, repository, document, resolver := resolvedDeliveredG00Fixture(t)
	defer repository.Close()
	writeFile(t, repository, "roadmap.yaml", document)
	record := decodeJSONObject(t, resolver[requirementEvidenceLocator].Payload)
	record["observedAt"] = "2026-07-20T00:00:00Z"
	replaceResolvedPayload(t, repository, resolver, requirementEvidenceLocator, marshalJSON(t, record))
	err := ValidateDirWithOptions(root, validationOptions(resolver))
	if err == nil || !strings.Contains(err.Error(), "evidence exceeds verifier freshness ceiling") {
		t.Fatalf("ValidateDirWithOptions() error = %v, want freshness-ceiling blocker", err)
	}
}

func TestValidateRejectsInvalidAttestationStatements(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, []byte) []byte
		want   string
	}{
		{
			name: "unknown member",
			mutate: func(t *testing.T, payload []byte) []byte {
				statement := decodeJSONObject(t, payload)
				statement["unknown"] = true
				return marshalJSON(t, statement)
			},
			want: "attestation statement is not a closed object",
		},
		{
			name: "duplicate member",
			mutate: func(_ *testing.T, payload []byte) []byte {
				return bytes.Replace(payload, []byte(`{`), []byte(`{"goal":"G00",`), 1)
			},
			want: "attestation statement is not strict JSON",
		},
		{
			name: "subject mismatch",
			mutate: func(t *testing.T, payload []byte) []byte {
				statement := decodeJSONObject(t, payload)
				statement["subjectDigest"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				return marshalJSON(t, statement)
			},
			want: "attestation subject digest mismatch",
		},
		{
			name: "tuple mismatch",
			mutate: func(t *testing.T, payload []byte) []byte {
				statement := decodeJSONObject(t, payload)
				statement["goal"] = "G01"
				return marshalJSON(t, statement)
			},
			want: "attestation tuple mismatch",
		},
		{
			name: "expired validity window",
			mutate: func(t *testing.T, payload []byte) []byte {
				statement := decodeJSONObject(t, payload)
				statement["validUntil"] = "2026-07-22T12:00:00Z"
				return marshalJSON(t, statement)
			},
			want: "attestation validity window is invalid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, repository, document, resolver := resolvedDeliveredG00Fixture(t)
			defer repository.Close()
			writeFile(t, repository, "roadmap.yaml", document)
			payload := test.mutate(t, resolver[attestationLocator].Payload)
			replaceRequirementAttestationPayload(t, repository, resolver, payload)
			err := ValidateDirWithOptions(root, validationOptions(resolver))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateDirWithOptions() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCanonicalEvidenceSubjectDetachesOnlyAttestation(t *testing.T) {
	_, repository, _, resolver := resolvedDeliveredG00Fixture(t)
	defer repository.Close()
	document, err := decodeStrictJSON(resolver[requirementEvidenceLocator].Payload)
	if err != nil {
		t.Fatal(err)
	}
	original, err := canonicalEvidenceSubject(document)
	if err != nil {
		t.Fatal(err)
	}

	record := document.(map[string]any)
	record["attestation"].(map[string]any)["digest"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	detached, err := canonicalEvidenceSubject(record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, detached) {
		t.Fatal("attestation self-reference changed the detached subject")
	}
	record["sourceSha"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	changed, err := canonicalEvidenceSubject(record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original, changed) {
		t.Fatal("non-attestation tuple change did not change the detached subject")
	}
}

func TestResolverSessionCapsAllAttemptsIncludingCachedObjects(t *testing.T) {
	resolver := make(memoryResolver)
	reference := addGenericReference(resolver, "protected://test/cached", []byte("cached descriptor"), false)
	var decoded evidenceReference
	data := marshalJSON(t, reference)
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	session := newResolverSession(validationOptions(resolver))
	for attempt := 0; attempt < maxEvidenceResolutions; attempt++ {
		if _, err := session.resolveReference(decoded, "cached", false); err != nil {
			t.Fatalf("attempt %d unexpectedly failed: %v", attempt, err)
		}
	}
	if _, err := session.resolveReference(decoded, "cached", false); err == nil || !strings.Contains(err.Error(), "attempt limit exceeded") {
		t.Fatalf("final attempt error = %v, want attempt-limit blocker", err)
	}
}

func TestResolverSessionCapsAggregateCachedBytes(t *testing.T) {
	resolver := make(memoryResolver)
	reference := addGenericReference(resolver, "protected://test/bytes", []byte("descriptor"), false)
	var decoded evidenceReference
	if err := json.Unmarshal(marshalJSON(t, reference), &decoded); err != nil {
		t.Fatal(err)
	}
	session := newResolverSession(validationOptions(resolver))
	session.bytes = maxResolvedEvidenceBytes - len(resolver[decoded.Locator].Payload) + 1
	if _, err := session.resolveReference(decoded, "bytes", false); err == nil || !strings.Contains(err.Error(), "aggregate byte limit exceeded") {
		t.Fatalf("resolveReference() error = %v, want aggregate-byte blocker", err)
	}
}

func TestValidateRejectsDeliveredStateWithoutExactDownstreamPin(t *testing.T) {
	root, repository, document := deliveredG00Fixture(t)
	defer repository.Close()
	writeFile(t, repository, "roadmap.yaml", document)
	state := validDeliveredG00State(t)
	state = strings.Replace(state,
		`"pin": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`,
		`"pin": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, 1)
	writeFile(t, repository, "state/G00.json", state)
	err := ValidateDir(root)
	if err == nil || !strings.Contains(err.Error(), "reference pin must equal the exact accepted public SHA") {
		t.Fatalf("ValidateDir() error = %v, want exact downstream pin blocker", err)
	}
}

func TestValidateRejectsDeliveredStateWithoutCleanupProof(t *testing.T) {
	root, repository, document := deliveredG00Fixture(t)
	defer repository.Close()
	writeFile(t, repository, "roadmap.yaml", document)
	state := validDeliveredG00State(t)
	state = strings.Replace(state, `"cleanup": "complete"`, `"cleanup": "not_applicable"`, 1)
	writeFile(t, repository, "state/G00.json", state)
	err := ValidateDir(root)
	if err == nil || !strings.Contains(err.Error(), "public clean-room deployment requires completed cleanup proof") {
		t.Fatalf("ValidateDir() error = %v, want cleanup-proof blocker", err)
	}
}

func TestValidateRejectsEveryInvalidStateFile(t *testing.T) {
	tests := []struct {
		name string
		file string
		body string
		want string
	}{
		{name: "unexpected extension", file: "state/G00.json.bak", body: `{}`, want: "unexpected state directory entry"},
		{name: "unknown goal", file: "state/G99.json", body: validDeliveredG00State(t), want: "goal must be G99"},
		{name: "invalid inactive record", file: "state/G02.json", body: `{}`, want: "does not satisfy state schema"},
		{name: "duplicate JSON key", file: "state/G00.json", body: strings.Replace(validDeliveredG00State(t), "{", "{\n  \"goal\": \"G00\",", 1), want: "duplicate JSON object key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, repository, document := writeFixture(t)
			defer repository.Close()
			if err := repository.MkdirAll("state", 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, repository, "roadmap.yaml", document)
			writeFile(t, repository, test.file, test.body)
			err := ValidateDir(root)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateDir() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateRejectsSymlinkedReferenceParent(t *testing.T) {
	root, repository, document := writeFixture(t)
	defer repository.Close()
	if err := repository.MkdirAll("actual-schemas", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := repository.Rename("state.schema.json", "actual-schemas/state.schema.json"); err != nil {
		t.Fatal(err)
	}
	if err := repository.Symlink("actual-schemas", "schema-link"); err != nil {
		t.Fatal(err)
	}
	document = strings.Replace(document, "stateSchema: state.schema.json", "stateSchema: schema-link/state.schema.json", 1)
	writeFile(t, repository, "roadmap.yaml", document)
	err := ValidateDir(root)
	if err == nil || !strings.Contains(err.Error(), "stateSchema: file reference must not traverse symbolic links") {
		t.Fatalf("ValidateDir() error = %v, want symlink-parent rejection", err)
	}
}

func TestValidateRejectsUnknownAndEmptyDeploymentTargets(t *testing.T) {
	tests := []struct {
		name       string
		oldTargets string
		newTargets string
		want       string
	}{
		{
			name:       "unknown default target",
			oldTargets: "defaultDeploymentTargets: [public_clean_room, hub]",
			newTargets: "defaultDeploymentTargets: [public_clean_room, hub, mystery]",
			want:       `default deployment targets contains unknown target "mystery"`,
		},
		{
			name:       "empty goal target",
			oldTargets: "deploymentTargets: [public_clean_room, hub, independent_provider] # G24",
			newTargets: "deploymentTargets: [public_clean_room, hub, independent_provider, \"\"] # G24",
			want:       "G24: deployment targets must not contain empty values",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, repository, document := writeFixture(t)
			defer repository.Close()
			document = strings.Replace(document, test.oldTargets, test.newTargets, 1)
			writeFile(t, repository, "roadmap.yaml", document)
			err := ValidateDir(root)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateDir() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidationBlockerOrderingIsDeterministic(t *testing.T) {
	root, repository, document := writeFixture(t)
	defer repository.Close()
	document = strings.Replace(document, "metadata:\n  name: test", "metadata:\n  name: \"\"", 1)
	document = strings.Replace(document, "defaultDeploymentTargets: [public_clean_room, hub]", "defaultDeploymentTargets: [public_clean_room, hub, mystery, \"\"]", 1)
	writeFile(t, repository, "roadmap.yaml", document)

	var first string
	for attempt := 0; attempt < 20; attempt++ {
		err := ValidateDir(root)
		if err == nil {
			t.Fatal("ValidateDir() unexpectedly succeeded")
		}
		if attempt == 0 {
			first = err.Error()
		} else if err.Error() != first {
			t.Fatalf("blocker order changed:\nfirst: %s\nlater: %s", first, err)
		}
	}
	lines := strings.Split(first, "\n")
	if !slices.IsSorted(lines) {
		t.Fatalf("blockers are not sorted: %v", lines)
	}
}

func deliveredG00Fixture(t *testing.T) (string, *os.Root, string) {
	t.Helper()
	root, repository, document := writeFixture(t)
	if err := repository.MkdirAll("state", 0o755); err != nil {
		if closeErr := repository.Close(); closeErr != nil {
			t.Fatalf("create state directory: %v; close fixture root: %v", err, closeErr)
		}
		t.Fatal(err)
	}
	document = strings.Replace(document, "status: not_started # G00", "status: delivered # G00", 1)
	writeFile(t, repository, "state/G00.json", validDeliveredG00State(t))
	return root, repository, document
}

func validDeliveredG00State(t *testing.T) string {
	t.Helper()
	return strings.ReplaceAll(
		strings.ReplaceAll(readShippedRoadmapFile(t, "examples/delivered-state.example.json"), "CR-G01-DEV-INSTALL", "CR-G00-DELIVERY"),
		"G01", "G00",
	)
}

func readShippedRoadmapFile(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// #nosec G304 -- name is a test-controlled fixture path anchored below roadmap.
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "roadmap", filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

const (
	requirementEvidenceLocator = "protected://test/evidence/requirement"
	attestationLocator         = "protected://test/attestation"
)

type memoryResolver map[string]ResolvedEvidence

func (r memoryResolver) Resolve(locator string) (ResolvedEvidence, error) {
	resolved, exists := r[locator]
	if !exists {
		return ResolvedEvidence{}, errors.New("not found")
	}
	return resolved, nil
}

func validationOptions(resolver memoryResolver) ValidationOptions {
	return ValidationOptions{
		EvidenceResolver: resolver,
		CurrentTime:      time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC),
		FreshnessCeilings: map[string]time.Duration{
			"G00": 48 * time.Hour,
		},
	}
}

func resolvedDeliveredG00Fixture(t *testing.T) (string, *os.Root, string, memoryResolver) {
	t.Helper()
	root, repository, document := deliveredG00Fixture(t)
	resolver := make(memoryResolver)
	state := decodeJSONObject(t, []byte(validDeliveredG00State(t)))

	release := addGenericReference(resolver, "protected://test/release", []byte("release manifest"), false)
	artifact := addGenericReference(resolver, "protected://test/artifact", []byte("release artifact"), false)
	publicProfile := addGenericReference(resolver, "protected://test/profile/public", []byte("public profile"), false)
	hubProfile := addGenericReference(resolver, "protected://test/profile/hub", []byte("hub profile"), false)
	proofArtifact := addGenericReference(resolver, "protected://test/proof", []byte("proof artifact"), false)

	state["artifacts"] = []any{artifact}
	state["releaseManifest"] = release
	state["predecessorRegression"] = nil

	requirementEvidence := addEvidenceRecord(
		t,
		resolver,
		requirementEvidenceLocator,
		release,
		publicProfile,
		proofArtifact,
		"ci",
		"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		nil,
	)
	requirementResults := state["requirementResults"].([]any)
	requirementResult := requirementResults[0].(map[string]any)
	requirementResult["evidence"] = []any{requirementEvidence}

	deployments := state["deployments"].([]any)
	publicDeployment := deployments[0].(map[string]any)
	publicDeployment["profile"] = publicProfile
	publicDeployment["evidence"] = []any{addEvidenceRecord(
		t,
		resolver,
		"protected://test/evidence/public",
		release,
		publicProfile,
		proofArtifact,
		"public_clean_room",
		"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		nil,
	)}
	hubRevision := "cccccccccccccccccccccccccccccccccccccccc"
	hubDeployment := deployments[1].(map[string]any)
	hubDeployment["profile"] = hubProfile
	hubDeployment["evidence"] = []any{addEvidenceRecord(
		t,
		resolver,
		"protected://test/evidence/hub",
		release,
		hubProfile,
		proofArtifact,
		"hub",
		"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		&hubRevision,
	)}

	writeFile(t, repository, "state/G00.json", string(marshalJSON(t, state)))
	return root, repository, document, resolver
}

func addEvidenceRecord(
	t *testing.T,
	resolver memoryResolver,
	locator string,
	release map[string]any,
	profile map[string]any,
	proofArtifact map[string]any,
	environmentClass string,
	environmentFingerprint string,
	gitOpsRevision *string,
) map[string]any {
	t.Helper()
	record := map[string]any{
		"goal":            "G00",
		"requirement":     "CR-G00-DELIVERY",
		"sourceSha":       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"releaseManifest": release,
		"observedAt":      "2026-07-22T00:00:00Z",
		"expiresAt":       "2026-08-22T00:00:00Z",
		"environment": map[string]any{
			"class":          environmentClass,
			"fingerprint":    environmentFingerprint,
			"profile":        profile,
			"gitOpsRevision": gitOpsRevision,
		},
		"verdict": "pass",
		"proof": map[string]any{
			"kind":     "test",
			"summary":  "Sanitized test proof.",
			"artifact": proofArtifact,
		},
		"redaction": map[string]any{
			"validatorVersion": "test-v1",
			"verdict":          "pass",
		},
		"cleanup": "complete",
	}
	statementLocator := locator + "/attestation"
	if locator == requirementEvidenceLocator {
		statementLocator = attestationLocator
	}
	record["attestation"] = map[string]any{
		"digest":         "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"locator":        statementLocator,
		"retentionUntil": "2035-01-01T00:00:00Z",
	}
	subject, err := canonicalEvidenceSubject(record)
	if err != nil {
		t.Fatal(err)
	}
	subjectDigest := sha256.Sum256(subject)
	statement := map[string]any{
		"subjectDigest":             fmt.Sprintf("sha256:%x", subjectDigest),
		"attestationLocator":        statementLocator,
		"attestationRetentionUntil": "2035-01-01T00:00:00Z",
		"goal":                      record["goal"],
		"requirement":               record["requirement"],
		"sourceSha":                 record["sourceSha"],
		"releaseManifest":           release,
		"environment":               record["environment"],
		"validFrom":                 "2026-07-22T00:00:00Z",
		"validUntil":                "2026-08-22T00:00:00Z",
	}
	record["attestation"] = addGenericReference(resolver, statementLocator, marshalJSON(t, statement), true)
	return addGenericReference(resolver, locator, marshalJSON(t, record), false)
}

func addGenericReference(resolver memoryResolver, locator string, payload []byte, trusted bool) map[string]any {
	digest := sha256.Sum256(payload)
	resolver[locator] = ResolvedEvidence{Payload: payload, Trusted: trusted}
	return map[string]any{
		"digest":         fmt.Sprintf("sha256:%x", digest),
		"locator":        locator,
		"retentionUntil": "2035-01-01T00:00:00Z",
	}
}

func replaceResolvedPayload(t *testing.T, repository *os.Root, resolver memoryResolver, locator string, payload []byte) {
	t.Helper()
	resolved := resolver[locator]
	resolved.Payload = payload
	resolver[locator] = resolved

	stateData, err := readRegular(repository, "state/G00.json")
	if err != nil {
		t.Fatal(err)
	}
	state := decodeJSONObject(t, stateData)
	digest := sha256.Sum256(payload)
	if !replaceReferenceDigest(state, locator, fmt.Sprintf("sha256:%x", digest)) {
		t.Fatalf("state reference for %s was not found", locator)
	}
	writeFile(t, repository, "state/G00.json", string(marshalJSON(t, state)))
}

func replaceRequirementAttestationPayload(
	t *testing.T,
	repository *os.Root,
	resolver memoryResolver,
	payload []byte,
) {
	t.Helper()
	resolved := resolver[attestationLocator]
	resolved.Payload = payload
	resolver[attestationLocator] = resolved

	record := decodeJSONObject(t, resolver[requirementEvidenceLocator].Payload)
	attestation := record["attestation"].(map[string]any)
	digest := sha256.Sum256(payload)
	attestation["digest"] = fmt.Sprintf("sha256:%x", digest)
	replaceResolvedPayload(t, repository, resolver, requirementEvidenceLocator, marshalJSON(t, record))
}

func referenceForResolverObject(resolver memoryResolver, locator string) map[string]any {
	resolved := resolver[locator]
	digest := sha256.Sum256(resolved.Payload)
	return map[string]any{
		"digest":         fmt.Sprintf("sha256:%x", digest),
		"locator":        locator,
		"retentionUntil": "2035-01-01T00:00:00Z",
	}
}

func replaceReferenceDigest(value any, locator, digest string) bool {
	found := false
	switch typed := value.(type) {
	case map[string]any:
		if typed["locator"] == locator {
			typed["digest"] = digest
			found = true
		}
		for _, child := range typed {
			if replaceReferenceDigest(child, locator, digest) {
				found = true
			}
		}
	case []any:
		for _, child := range typed {
			if replaceReferenceDigest(child, locator, digest) {
				found = true
			}
		}
	}
	return found
}

func decodeJSONObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func marshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return data
}
