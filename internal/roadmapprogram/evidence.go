// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package roadmapprogram

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The program-wide ceiling accommodates all 28 cumulative goal records and
// their nested descriptors while still bounding resolver work independently of
// input size.
const maxEvidenceResolutions = 4096

const (
	maxResolvedEvidenceBytes = 64 << 20
	maxGoalEvidenceFreshness = 90 * 24 * time.Hour
)

// EvidenceResolver supplies already-authorized evidence bytes for one exact
// locator. The roadmap validator itself performs no network or process access.
// Implementations must keep authorization and transport policy outside this
// package.
type EvidenceResolver interface {
	Resolve(locator string) (ResolvedEvidence, error)
}

// ResolvedEvidence is the bounded descriptor or evidence record returned by an
// EvidenceResolver. Release references must therefore resolve to a small,
// content-addressed descriptor, not stream a release binary through validation.
// Trusted is required only for attestation objects; it lets the resolver report
// that its caller-defined trust policy accepted the exact resolved bytes.
type ResolvedEvidence struct {
	Payload []byte
	Trusted bool
}

// ValidationOptions are explicit inputs for evidence-bearing validation.
// CurrentTime may be fixed by CI; a zero value uses the current UTC time.
type ValidationOptions struct {
	EvidenceResolver EvidenceResolver
	CurrentTime      time.Time
	// FreshnessCeilings is required per goal whenever a resolver is used for
	// proof. A verifier may choose a stricter duration, but never more than the
	// program-wide safety ceiling.
	FreshnessCeilings map[string]time.Duration
}

type resolvedObject struct {
	payload []byte
	trusted bool
}

type resolverSession struct {
	resolver  EvidenceResolver
	now       time.Time
	objects   map[string]resolvedObject
	freshness map[string]time.Duration
	attempts  int
	count     int
	bytes     int
}

type evidenceExpectation struct {
	goal            string
	requirement     string
	requirements    []string
	sourceSHA       string
	releaseManifest *evidenceReference
	target          string
	fingerprint     string
	profile         *evidenceReference
	gitOpsRevision  *string
	requirePass     bool
	maxAge          time.Duration
}

type evidenceRecord struct {
	Goal            string            `json:"goal"`
	Requirement     string            `json:"requirement"`
	SourceSHA       string            `json:"sourceSha"`
	ReleaseManifest evidenceReference `json:"releaseManifest"`
	ObservedAt      string            `json:"observedAt"`
	ExpiresAt       string            `json:"expiresAt"`
	Environment     struct {
		Class          string            `json:"class"`
		Fingerprint    string            `json:"fingerprint"`
		Profile        evidenceReference `json:"profile"`
		GitOpsRevision *string           `json:"gitOpsRevision"`
	} `json:"environment"`
	Verdict string `json:"verdict"`
	Proof   struct {
		Artifact evidenceReference `json:"artifact"`
	} `json:"proof"`
	Measurement *struct {
		Thresholds evidenceReference `json:"thresholds"`
		Results    evidenceReference `json:"results"`
	} `json:"measurement"`
	Redaction struct {
		Verdict string `json:"verdict"`
	} `json:"redaction"`
	Attestation evidenceReference `json:"attestation"`
}

type attestationStatement struct {
	SubjectDigest             string            `json:"subjectDigest"`
	AttestationLocator        string            `json:"attestationLocator"`
	AttestationRetentionUntil string            `json:"attestationRetentionUntil"`
	Goal                      string            `json:"goal"`
	Requirement               string            `json:"requirement"`
	SourceSHA                 string            `json:"sourceSha"`
	ReleaseManifest           evidenceReference `json:"releaseManifest"`
	Environment               struct {
		Class          string            `json:"class"`
		Fingerprint    string            `json:"fingerprint"`
		Profile        evidenceReference `json:"profile"`
		GitOpsRevision *string           `json:"gitOpsRevision"`
	} `json:"environment"`
	ValidFrom  string `json:"validFrom"`
	ValidUntil string `json:"validUntil"`
}

func newResolverSession(options ValidationOptions) *resolverSession {
	now := options.CurrentTime
	if now.IsZero() {
		now = time.Now().UTC()
	}
	freshness := make(map[string]time.Duration, len(options.FreshnessCeilings))
	for goal, ceiling := range options.FreshnessCeilings {
		freshness[goal] = ceiling
	}
	return &resolverSession{
		resolver:  options.EvidenceResolver,
		now:       now,
		objects:   make(map[string]resolvedObject),
		freshness: freshness,
	}
}

func (s *resolverSession) freshnessCeiling(goal string) (time.Duration, error) {
	ceiling, exists := s.freshness[goal]
	if !exists {
		return 0, fmt.Errorf("%s: verifier freshness ceiling is required", goal)
	}
	if ceiling <= 0 || ceiling > maxGoalEvidenceFreshness {
		return 0, fmt.Errorf("%s: verifier freshness ceiling is outside the allowed range", goal)
	}
	return ceiling, nil
}

func (s *resolverSession) resolveReference(reference evidenceReference, label string, requireTrusted bool) ([]byte, error) {
	retentionUntil, err := time.Parse(time.RFC3339, reference.RetentionUntil)
	if err != nil || !retentionUntil.After(s.now) {
		return nil, fmt.Errorf("%s: evidence retention has expired", label)
	}
	if s.resolver == nil {
		return nil, fmt.Errorf("%s: evidence is unresolved", label)
	}
	if s.attempts >= maxEvidenceResolutions {
		return nil, errors.New("evidence resolution attempt limit exceeded")
	}
	s.attempts++

	object, exists := s.objects[reference.Locator]
	if !exists {
		if s.count >= maxEvidenceResolutions {
			return nil, errors.New("evidence resolution limit exceeded")
		}
		// Count the unique object before invoking caller-controlled resolver code;
		// failed or oversized attempts still consume the bounded work budget.
		s.count++
		resolved, resolveErr := s.resolver.Resolve(reference.Locator)
		if resolveErr != nil {
			return nil, fmt.Errorf("%s: evidence is unresolved", label)
		}
		if len(resolved.Payload) == 0 || len(resolved.Payload) > maxRoadmapFileBytes {
			return nil, fmt.Errorf("%s: resolved evidence is not a bounded object", label)
		}
		if len(resolved.Payload) > maxResolvedEvidenceBytes-s.bytes {
			return nil, errors.New("resolved evidence aggregate byte limit exceeded")
		}
		object = resolvedObject{payload: bytes.Clone(resolved.Payload), trusted: resolved.Trusted}
		s.objects[reference.Locator] = object
		s.bytes += len(object.payload)
	}

	digest := sha256.Sum256(object.payload)
	if reference.Digest != fmt.Sprintf("sha256:%x", digest) {
		return nil, fmt.Errorf("%s: evidence digest mismatch", label)
	}
	if requireTrusted && !object.trusted {
		return nil, fmt.Errorf("%s: attestation trust policy did not pass", label)
	}
	return object.payload, nil
}

func (s *resolverSession) validateEvidenceRecord(
	reference evidenceReference,
	label string,
	schema *jsonschema.Schema,
	expectation evidenceExpectation,
) error {
	payload, err := s.resolveReference(reference, label, false)
	if err != nil {
		return err
	}
	document, err := decodeStrictJSON(payload)
	if err != nil {
		return fmt.Errorf("%s: evidence record is not strict JSON", label)
	}
	if err := schema.Validate(document); err != nil {
		return fmt.Errorf("%s: evidence record does not satisfy evidence schema", label)
	}
	var record evidenceRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return fmt.Errorf("%s: evidence record cannot be decoded", label)
	}

	if record.Goal != expectation.goal {
		return fmt.Errorf("%s: evidence goal tuple mismatch", label)
	}
	if expectation.requirement != "" {
		if record.Requirement != expectation.requirement {
			return fmt.Errorf("%s: evidence requirement tuple mismatch", label)
		}
	} else if !contains(expectation.requirements, record.Requirement) {
		return fmt.Errorf("%s: evidence requirement tuple mismatch", label)
	}
	if expectation.sourceSHA == "" || record.SourceSHA != expectation.sourceSHA {
		return fmt.Errorf("%s: evidence source tuple mismatch", label)
	}
	if expectation.releaseManifest == nil || record.ReleaseManifest != *expectation.releaseManifest {
		return fmt.Errorf("%s: evidence release tuple mismatch", label)
	}
	if record.Redaction.Verdict != "pass" {
		return fmt.Errorf("%s: evidence redaction verdict did not pass", label)
	}
	if expectation.requirePass && record.Verdict != "pass" {
		return fmt.Errorf("%s: delivered evidence verdict did not pass", label)
	}

	observedAt, observedErr := time.Parse(time.RFC3339, record.ObservedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339, record.ExpiresAt)
	if observedErr != nil || expiresErr != nil || !observedAt.Before(expiresAt) {
		return fmt.Errorf("%s: evidence observation interval is invalid", label)
	}
	if observedAt.After(s.now) {
		return fmt.Errorf("%s: evidence observation is in the future", label)
	}
	if !expiresAt.After(s.now) {
		return fmt.Errorf("%s: evidence record has expired", label)
	}
	if expectation.maxAge <= 0 || s.now.Sub(observedAt) > expectation.maxAge {
		return fmt.Errorf("%s: evidence exceeds verifier freshness ceiling", label)
	}

	if expectation.target != "" {
		if record.Environment.Class != evidenceEnvironmentClass(expectation.target) {
			return fmt.Errorf("%s: evidence environment tuple mismatch", label)
		}
		if !equalOptionalString(record.Environment.GitOpsRevision, expectation.gitOpsRevision) {
			return fmt.Errorf("%s: evidence GitOps tuple mismatch", label)
		}
		if record.Environment.Fingerprint != expectation.fingerprint {
			return fmt.Errorf("%s: evidence environment fingerprint mismatch", label)
		}
		if expectation.profile == nil || record.Environment.Profile != *expectation.profile {
			return fmt.Errorf("%s: evidence environment profile mismatch", label)
		}
	}

	nested := []struct {
		label     string
		reference evidenceReference
		trusted   bool
	}{
		{label: label + " release manifest", reference: record.ReleaseManifest},
		{label: label + " environment profile", reference: record.Environment.Profile},
		{label: label + " proof artifact", reference: record.Proof.Artifact},
	}
	if record.Measurement != nil {
		nested = append(nested,
			struct {
				label     string
				reference evidenceReference
				trusted   bool
			}{label: label + " measurement thresholds", reference: record.Measurement.Thresholds},
			struct {
				label     string
				reference evidenceReference
				trusted   bool
			}{label: label + " measurement results", reference: record.Measurement.Results},
		)
	}
	for _, item := range nested {
		if _, err := s.resolveReference(item.reference, item.label, item.trusted); err != nil {
			return err
		}
	}
	return s.validateAttestation(record.Attestation, document, record, label+" attestation")
}

func (s *resolverSession) validateAttestation(
	reference evidenceReference,
	evidenceDocument any,
	record evidenceRecord,
	label string,
) error {
	payload, err := s.resolveReference(reference, label, true)
	if err != nil {
		return err
	}
	if _, err := decodeStrictJSON(payload); err != nil {
		return fmt.Errorf("%s: attestation statement is not strict JSON", label)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var statement attestationStatement
	if err := decoder.Decode(&statement); err != nil {
		return fmt.Errorf("%s: attestation statement is not a closed object", label)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: attestation statement has trailing data", label)
	}

	subject, err := canonicalEvidenceSubject(evidenceDocument)
	if err != nil {
		return fmt.Errorf("%s: evidence subject cannot be canonicalized", label)
	}
	subjectDigest := sha256.Sum256(subject)
	if statement.SubjectDigest != fmt.Sprintf("sha256:%x", subjectDigest) {
		return fmt.Errorf("%s: attestation subject digest mismatch", label)
	}
	if statement.AttestationLocator != reference.Locator || statement.AttestationRetentionUntil != reference.RetentionUntil {
		return fmt.Errorf("%s: attestation reference binding mismatch", label)
	}
	if statement.Goal != record.Goal || statement.Requirement != record.Requirement ||
		statement.SourceSHA != record.SourceSHA || statement.ReleaseManifest != record.ReleaseManifest ||
		statement.Environment.Class != record.Environment.Class ||
		statement.Environment.Fingerprint != record.Environment.Fingerprint ||
		statement.Environment.Profile != record.Environment.Profile ||
		!equalOptionalString(statement.Environment.GitOpsRevision, record.Environment.GitOpsRevision) {
		return fmt.Errorf("%s: attestation tuple mismatch", label)
	}
	validFrom, fromErr := time.Parse(time.RFC3339, statement.ValidFrom)
	validUntil, untilErr := time.Parse(time.RFC3339, statement.ValidUntil)
	if fromErr != nil || untilErr != nil || !validFrom.Before(validUntil) || s.now.Before(validFrom) || !s.now.Before(validUntil) {
		return fmt.Errorf("%s: attestation validity window is invalid", label)
	}
	return nil
}

// canonicalEvidenceSubject produces the detached attestation subject. It
// canonicalizes the already strict evidence JSON with exactly one transformation:
// removal of the top-level attestation member. Removing the self-reference avoids
// a cryptographic digest cycle; every other member and nested value remains bound.
func canonicalEvidenceSubject(document any) ([]byte, error) {
	object, ok := document.(map[string]any)
	if !ok {
		return nil, errors.New("evidence subject must be an object")
	}
	detached := make(map[string]any, len(object)-1)
	for key, value := range object {
		if key != "attestation" {
			detached[key] = value
		}
	}
	if _, exists := object["attestation"]; !exists {
		return nil, errors.New("evidence subject has no attestation member")
	}
	return json.Marshal(detached)
}

func evidenceEnvironmentClass(target string) string {
	switch target {
	case "region_primary", "region_secondary":
		return "region"
	case "federation_provider_a", "federation_provider_b":
		return "federation_provider"
	default:
		return target
	}
}

func equalOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
