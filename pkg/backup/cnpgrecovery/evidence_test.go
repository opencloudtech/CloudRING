// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package cnpgrecovery

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestVerifyEvidenceAcceptsExactProof(t *testing.T) {
	payload := marshalPostgreSQLRecoveryEvidence(t, validPostgreSQLRecoveryEvidence())
	if err := VerifyEvidence(bytes.NewReader(payload)); err != nil {
		t.Fatalf("exact recovery evidence was rejected: %v", err)
	}
	if err := VerifyEvidenceForRevision(bytes.NewReader(payload), strings.Repeat("a", 40)); err != nil {
		t.Fatalf("revision-bound recovery evidence was rejected: %v", err)
	}
}

func TestVerifyEvidenceForRevisionRejectsDifferentOrInvalidRevision(t *testing.T) {
	payload := marshalPostgreSQLRecoveryEvidence(t, validPostgreSQLRecoveryEvidence())
	for _, revision := range []string{strings.Repeat("b", 40), "main", ""} {
		if err := VerifyEvidenceForRevision(bytes.NewReader(payload), revision); err == nil {
			t.Fatalf("recovery evidence accepted for revision %q", revision)
		}
	}
}

func TestVerifyEvidenceRejectsAdversarialProofs(t *testing.T) {
	failureTime := "2026-07-23T00:03:30Z"
	tests := []struct {
		name   string
		mutate func(*Evidence)
	}{
		{"checksum mismatch", func(value *Evidence) {
			value.Checksum.Recovered = "sha256:" + strings.Repeat("b", 64)
		}},
		{"source bytes absent", func(value *Evidence) { value.Checksum.SourceLogicalBytes = 0 }},
		{"recovered bytes differ", func(value *Evidence) { value.Checksum.RecoveredLogicalBytes++ }},
		{"row count absent", func(value *Evidence) { value.Checksum.SourceRowCount = 0 }},
		{"row count differs", func(value *Evidence) { value.Checksum.RecoveredRowCount++ }},
		{"backup not ordered", func(value *Evidence) { value.BaseBackup.StartedAt = value.BaseBackup.CompletedAt }},
		{"WAL does not cover source", func(value *Evidence) { value.WALArchive.LastArchivedAt = "2026-07-23T00:02:30Z" }},
		{"WAL failure retained", func(value *Evidence) { value.WALArchive.LastFailedAt = &failureTime }},
		{"WAL replay timestamp after recovered checksum", func(value *Evidence) { value.WALArchive.ReplayedThrough = "2026-07-23T02:13:00Z" }},
		{"recovery starts before archive", func(value *Evidence) { value.Recovery.StartedAt = "2026-07-23T00:03:30Z" }},
		{"recovery starts at archive boundary", func(value *Evidence) { value.Recovery.StartedAt = value.WALArchive.LastArchivedAt }},
		{"checksum before recovery Ready", func(value *Evidence) { value.Checksum.RecoveredCapturedAt = "2026-07-23T00:05:30Z" }},
		{"cleanup starts before validation", func(value *Evidence) { value.Cleanup.StartedAt = "2026-07-23T00:06:30Z" }},
		{"cleanup starts at validation boundary", func(value *Evidence) { value.Cleanup.StartedAt = value.Recovery.ValidatedAt }},
		{"only one cleanup sweep", func(value *Evidence) { value.Cleanup.Sweeps = value.Cleanup.Sweeps[:1] }},
		{"quiet window too small", func(value *Evidence) { value.Cleanup.Sweeps[1].ObservedAt = "2026-07-23T00:09:10Z" }},
		{"residual PVC", func(value *Evidence) { value.Cleanup.Sweeps[1].PersistentVolumeClaimCount = 1 }},
		{"cleanup incomplete", func(value *Evidence) { value.Cleanup.Complete = false }},
		{"cleanup completes at second sweep", func(value *Evidence) {
			value.Cleanup.CompletedAt = value.Cleanup.Sweeps[1].ObservedAt
		}},
		{"collection occurs at cleanup completion", func(value *Evidence) { value.CollectedAt = value.Cleanup.CompletedAt }},
		{"production route observed", func(value *Evidence) { value.Recovery.ProductionRouteCount = 1 }},
		{"credential disclosure", func(value *Evidence) { value.Redaction.ContainsCredentials = true }},
		{"evidence expires before collection", func(value *Evidence) { value.ExpiresAt = value.CollectedAt }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validPostgreSQLRecoveryEvidence()
			test.mutate(&value)
			if err := VerifyEvidence(bytes.NewReader(marshalPostgreSQLRecoveryEvidence(t, value))); err == nil {
				t.Fatal("unsafe recovery evidence was accepted")
			}
		})
	}
}

func TestVerifyEvidenceRejectsMissingZeroAndNullFields(t *testing.T) {
	tests := []struct {
		name string
		path []any
	}{
		{name: "WAL last failure", path: []any{"walArchive", "lastFailedAt"}},
		{name: "production route count", path: []any{"recovery", "productionRouteCount"}},
		{name: "recovery namespace count", path: []any{"cleanup", "sweeps", 0, "recoveryNamespaceCount"}},
		{name: "cluster count", path: []any{"cleanup", "sweeps", 0, "clusterCount"}},
		{name: "credential Secret count", path: []any{"cleanup", "sweeps", 0, "accessObjectCount"}},
		{name: "PVC count", path: []any{"cleanup", "sweeps", 0, "persistentVolumeClaimCount"}},
		{name: "Service count", path: []any{"cleanup", "sweeps", 0, "serviceCount"}},
		{name: "route count", path: []any{"cleanup", "sweeps", 0, "routeCount"}},
		{name: "credential redaction", path: []any{"redaction", "containsCredentials"}},
		{name: "endpoint redaction", path: []any{"redaction", "containsEndpoints"}},
		{name: "tenant redaction", path: []any{"redaction", "containsTenantData"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := marshalPostgreSQLRecoveryEvidence(t, validPostgreSQLRecoveryEvidence())
			payload = removePostgreSQLRecoveryEvidenceField(t, payload, test.path...)
			if err := VerifyEvidence(bytes.NewReader(payload)); err == nil {
				t.Fatal("evidence with an omitted required field was accepted")
			}
		})
	}
}

func TestVerifyEvidenceRejectsDuplicateAndUnknownFields(t *testing.T) {
	payload := marshalPostgreSQLRecoveryEvidence(t, validPostgreSQLRecoveryEvidence())
	duplicate := bytes.Replace(payload, []byte(`"verdict":"pass"`), []byte(`"verdict":"pass","verdict":"pass"`), 1)
	if err := VerifyEvidence(bytes.NewReader(duplicate)); err == nil {
		t.Fatal("duplicate evidence field was accepted")
	}
	unknown := bytes.Replace(payload, []byte(`"schemaVersion":`), []byte(`"unknown":true,"schemaVersion":`), 1)
	if err := VerifyEvidence(bytes.NewReader(unknown)); err == nil {
		t.Fatal("unknown evidence field was accepted")
	}
}

func validPostgreSQLRecoveryEvidence() Evidence {
	digest := "sha256:" + strings.Repeat("a", 64)
	evidence := Evidence{
		SchemaVersion:  EvidenceSchemaVersion,
		SourceRevision: strings.Repeat("a", 40),
		CollectedAt:    "2026-07-23T00:12:00Z",
		ExpiresAt:      "2026-07-23T02:12:00Z",
		OffCell: OffCellEvidence{
			ObservedAt: "2026-07-23T00:00:00Z", DestinationIdentity: digest,
			FailureDomainDistinct: true, RetentionDays: 30, ObjectLockMode: "governance",
			ObjectLockMinimumDays: 30, ControlDeleteDenied: true,
		},
		BaseBackup: BaseBackupEvidence{
			Identity: digest, StartedAt: "2026-07-23T00:01:00Z", CompletedAt: "2026-07-23T00:02:00Z",
			Status: "completed", Bytes: 4096, ObjectInventoryDigest: digest,
		},
		WALArchive: WALArchiveEvidence{
			FirstRecoverabilityPoint: "2026-07-22T23:00:00Z", LastArchivedAt: "2026-07-23T00:04:00Z",
			LastFailedAt: nil, ReplayedThrough: "2026-07-23T00:03:00Z", Continuous: true,
		},
		Recovery: RecoveryClusterEvidence{
			NamespaceIdentity: digest, ClusterIdentity: digest, SourceIdentity: digest,
			StartedAt: "2026-07-23T00:05:00Z", ReadyAt: "2026-07-23T00:06:00Z", ValidatedAt: "2026-07-23T00:07:00Z",
			ReadyInstances: 1, ExpectedInstances: 1, ProductionRouteCount: 0, WriteProbePassed: true,
		},
		Checksum: ChecksumEvidence{
			Algorithm: "sha256", ProjectionVersion: "cloudring-postgresql-logical-state/v1",
			Source: digest, Recovered: digest, SourceCapturedAt: "2026-07-23T00:03:00Z",
			RecoveredCapturedAt: "2026-07-23T00:06:30Z", SourceLogicalBytes: 2048,
			RecoveredLogicalBytes: 2048, SourceRowCount: 8, RecoveredRowCount: 8, Matched: true,
		},
		Cleanup: CleanupEvidence{
			StartedAt: "2026-07-23T00:08:00Z", CompletedAt: "2026-07-23T00:11:00Z",
			Complete: true, TwoSweepQuietWindowSeconds: 30,
			Sweeps: []CleanupSweepEvidence{
				{ObservedAt: "2026-07-23T00:09:00Z", InventoryDigest: digest},
				{ObservedAt: "2026-07-23T00:10:00Z", InventoryDigest: digest},
			},
		},
		Redaction: RedactionEvidence{Verdict: "pass"},
		Verdict:   "pass",
	}
	addValidRecoveryAssurance(&evidence)
	return evidence
}

func marshalPostgreSQLRecoveryEvidence(t *testing.T, evidence Evidence) []byte {
	t.Helper()
	payload, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func removePostgreSQLRecoveryEvidenceField(t *testing.T, payload []byte, path ...any) []byte {
	t.Helper()
	var document any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	current := document
	for _, segment := range path[:len(path)-1] {
		switch value := segment.(type) {
		case string:
			current = current.(map[string]any)[value]
		case int:
			current = current.([]any)[value]
		default:
			t.Fatalf("unsupported path segment %T", segment)
		}
	}
	field, ok := path[len(path)-1].(string)
	if !ok {
		t.Fatal("final path segment is not an object field")
	}
	delete(current.(map[string]any), field)
	result, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
