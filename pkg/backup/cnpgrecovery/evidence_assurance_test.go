// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package cnpgrecovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/transactionalstate"
)

func syntheticRecoveryIdentity(name string) string {
	digest := sha256.Sum256([]byte("synthetic-recovery-evidence-" + name))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func addValidRecoveryAssurance(e *Evidence) {
	id := syntheticRecoveryIdentity
	e.Consistency = ConsistencyEvidence{
		Method: ConsistencyMethod, BoundaryDigest: id("boundary"), SourceIdentity: e.Recovery.SourceIdentity,
		PrimaryIdentity: id("primary"), SnapshotIdentity: id("snapshot"), SnapshotIsolation: "repeatable read",
		SnapshotReadOnly: true, SnapshotBoundsEqual: true, LogicalCatalogSameSnapshot: true,
		MarkerIdentity: id("marker"), MarkerLSNIdentity: id("lsn"), MarkerWALIdentity: id("wal"),
		MarkerNameUnique: true, MarkerStatementsOrdered: true, MarkerSameTransaction: true, MarkerCommitConfirmed: true,
		FirstXIDMatchesSnapshot: true, SourceIdentityUnchanged: true,
		MarkerCreatedAt: "2026-07-23T00:03:10Z", QualifiedAt: "2026-07-23T00:03:11Z", ArchiveVerifiedAt: "2026-07-23T00:04:10Z",
		ArchivedMarkerWALIdentity: id("wal"), ArchiveObjectIdentity: id("archive-object"), ExactMarkerArchived: true,
		BaseBackupPrecedesMarker: true, RecoveredMarkerIdentity: id("marker"), RecoveredLSNIdentity: id("lsn"),
		RecoveredTargetVerifiedAt: "2026-07-23T00:06:10Z", ExactRecoveredTargetVerified: true,
	}
	e.WALArchive.ReplayedThrough = e.Consistency.MarkerCreatedAt
	binding := RecoveryAccessBinding{
		PrincipalIdentity: id("reader"), PolicyIdentity: id("policy"), PolicyRevisionIdentity: id("policy-revision"),
		SecretIdentity: id("secret"), SecretVersionIdentity: id("secret-version"),
		DestinationIdentity: e.OffCell.DestinationIdentity, ScopeIdentity: id("read-scope"),
	}
	e.RecoveryAccess = RecoveryAccessEvidence{
		Expected: binding, Observed: binding, WriterPrincipalIdentity: id("writer"),
		VerifiedAt: "2026-07-23T00:04:20Z", ExpiresAt: "2026-07-23T02:00:00Z", CredentialExpiresAt: nil,
		CredentialExpiryChecked: true, IndependentPolicyVerified: true, RequiredReadPermissions: true,
		WriteDenied: true, DeleteDenied: true, AdministrationDenied: true, OutsideScopeDenied: true,
		BaseBackupIdentity: e.BaseBackup.Identity, MarkerWALIdentity: e.Consistency.MarkerWALIdentity,
		BaseBackupReadPassed: true, MarkerWALReadPassed: true, AllowlistedProjectionOnly: true, SourceBindingUnchanged: true,
	}
	e.Catalog = CatalogEvidence{
		ContractVersion: transactionalstate.RecoveryContractSchemaVersion,
		OwnerIdentity:   id("database-owner"), ApplicationIdentity: id("database-application"),
		SourceSnapshotIdentity: e.Consistency.SnapshotIdentity, Source: id("catalog"), Recovered: id("catalog"),
		SourceCapturedAt: e.Checksum.SourceCapturedAt, RecoveredCapturedAt: e.Checksum.RecoveredCapturedAt,
		SourceContractValid: true, RecoveredContractValid: true,
	}
	e.Application = ApplicationEvidence{
		PrincipalIdentity: e.Catalog.ApplicationIdentity, StartedAt: "2026-07-23T00:06:31Z", CompletedAt: "2026-07-23T00:06:40Z",
		Authenticated: true, IdentityVerified: true, RolledBack: true, PostProbeCapturedAt: "2026-07-23T00:06:45Z",
		PostProbeLogicalDigest: e.Checksum.Recovered, PostProbeCatalogDigest: e.Catalog.Recovered,
	}
	for _, operation := range applicationAllowOrder {
		e.Application.Allowed = append(e.Application.Allowed, ApplicationAllowEvidence{Operation: operation, PrincipalIdentity: e.Catalog.ApplicationIdentity, AffectedRows: 1, ValuesMatched: true})
	}
	for _, operation := range applicationDenyOrder {
		e.Application.Denied = append(e.Application.Denied, ApplicationDenyEvidence{Operation: operation, PrincipalIdentity: e.Catalog.ApplicationIdentity, SQLState: "42501"})
	}
	rows := []int64{1, 3, 2, 3, 8}
	for index, name := range logicalClassOrder {
		e.Classes = append(e.Classes, LogicalClassEvidence{DataClass: name, Source: id(name), Recovered: id(name), SourceBytes: 128, RecoveredBytes: 128, SourceRows: rows[index], RecoveredRows: rows[index], Matched: true})
	}
	combined := &e.Classes[len(e.Classes)-1]
	combined.Source, combined.Recovered = e.Checksum.Source, e.Checksum.Recovered
	combined.SourceBytes, combined.RecoveredBytes = e.Checksum.SourceLogicalBytes, e.Checksum.RecoveredLogicalBytes
}

func rejectRecoveryEvidence(t *testing.T, evidence Evidence) {
	t.Helper()
	if err := VerifyEvidence(bytes.NewReader(marshalPostgreSQLRecoveryEvidence(t, evidence))); err == nil {
		t.Fatal("incomplete or inconsistent recovery evidence was accepted")
	}
}

func TestEvidenceV2RequiresEveryAssuranceFact(t *testing.T) {
	payload := marshalPostgreSQLRecoveryEvidence(t, validPostgreSQLRecoveryEvidence())
	var root map[string]any
	if json.Unmarshal(payload, &root) != nil {
		t.Fatal("decode synthetic recovery fixture")
	}
	var visit func(any, []any)
	visit = func(value any, path []any) {
		if len(path) > 0 {
			name := fmt.Sprint(path)
			t.Run(name+"-missing", func(t *testing.T) {
				changed := removePostgreSQLRecoveryEvidenceField(t, payload, path...)
				if VerifyEvidence(bytes.NewReader(changed)) == nil {
					t.Fatal("missing assurance fact was accepted")
				}
			})
			if value != nil { // credentialExpiresAt deliberately reports checked non-expiry with null.
				t.Run(name+"-null", func(t *testing.T) {
					changed := replaceRecoveryEvidenceField(t, payload, path, nil)
					if VerifyEvidence(bytes.NewReader(changed)) == nil {
						t.Fatal("null assurance fact was accepted")
					}
				})
			}
		}
		switch object := value.(type) {
		case map[string]any:
			for key, child := range object {
				visit(child, append(append([]any{}, path...), key))
			}
		case []any:
			// Entries have one shared exact object shape; substitution tests below
			// separately exercise every operation and every protected data class.
			if len(object) > 0 {
				if entry, ok := object[0].(map[string]any); ok {
					for key, child := range entry {
						visit(child, append(append([]any{}, path...), 0, key))
					}
				}
			}
		}
	}
	for _, field := range []string{"consistency", "recoveryAccess", "catalog", "application", "classes"} {
		visit(root[field], []any{field})
	}
}

func TestEvidenceV2RejectsEveryFalseQualification(t *testing.T) {
	for _, section := range []string{"Consistency", "RecoveryAccess", "Catalog", "Application"} {
		value := validPostgreSQLRecoveryEvidence()
		fields := reflect.ValueOf(&value).Elem().FieldByName(section)
		for index := 0; index < fields.NumField(); index++ {
			if fields.Field(index).Kind() != reflect.Bool {
				continue
			}
			name := fields.Type().Field(index).Name
			t.Run(section+"/"+name, func(t *testing.T) {
				evidence := validPostgreSQLRecoveryEvidence()
				field := reflect.ValueOf(&evidence).Elem().FieldByName(section).FieldByName(name)
				field.SetBool(!field.Bool())
				rejectRecoveryEvidence(t, evidence)
			})
		}
	}
}

func TestEvidenceV2RejectsSubstitutedBindingsAndCounts(t *testing.T) {
	other := syntheticRecoveryIdentity("substitution")
	tests := map[string]func(*Evidence){
		"old-schema":                 func(e *Evidence) { e.SchemaVersion = "cloudring.postgresql-cnpg-offcell-recovery-evidence/v1" },
		"wrong-method":               func(e *Evidence) { e.Consistency.Method = "equal-hashes" },
		"active-writer":              func(e *Evidence) { e.Consistency.SnapshotActiveXIDCount = 1 },
		"negative-writer-count":      func(e *Evidence) { e.Consistency.SnapshotActiveXIDCount = -1 },
		"wrong-isolation":            func(e *Evidence) { e.Consistency.SnapshotIsolation = "read committed" },
		"different-primary-source":   func(e *Evidence) { e.Consistency.SourceIdentity = other },
		"different-marker-segment":   func(e *Evidence) { e.Consistency.ArchivedMarkerWALIdentity = other },
		"different-recovered-marker": func(e *Evidence) { e.Consistency.RecoveredMarkerIdentity = other },
		"different-recovered-lsn":    func(e *Evidence) { e.Consistency.RecoveredLSNIdentity = other },
		"reader-is-writer": func(e *Evidence) {
			e.RecoveryAccess.WriterPrincipalIdentity = e.RecoveryAccess.Expected.PrincipalIdentity
		},
		"read-other-backup": func(e *Evidence) { e.RecoveryAccess.BaseBackupIdentity = other },
		"read-other-wal":    func(e *Evidence) { e.RecoveryAccess.MarkerWALIdentity = other },
		"read-other-destination": func(e *Evidence) {
			e.RecoveryAccess.Expected.DestinationIdentity = other
			e.RecoveryAccess.Observed.DestinationIdentity = other
		},
		"catalog-other-contract":         func(e *Evidence) { e.Catalog.ContractVersion = "unverified" },
		"catalog-owner-is-app":           func(e *Evidence) { e.Catalog.OwnerIdentity = e.Catalog.ApplicationIdentity },
		"catalog-other-snapshot":         func(e *Evidence) { e.Catalog.SourceSnapshotIdentity = other },
		"catalog-restored-drift":         func(e *Evidence) { e.Catalog.Recovered = other },
		"app-other-principal":            func(e *Evidence) { e.Application.PrincipalIdentity = other },
		"missing-allow":                  func(e *Evidence) { e.Application.Allowed = e.Application.Allowed[1:] },
		"missing-deny":                   func(e *Evidence) { e.Application.Denied = e.Application.Denied[1:] },
		"document-residue":               func(e *Evidence) { e.Application.ResidualDocumentRows = 1 },
		"audit-residue":                  func(e *Evidence) { e.Application.ResidualAuditRows = 1 },
		"negative-residue":               func(e *Evidence) { e.Application.ResidualAuditRows = -1 },
		"post-probe-logical-drift":       func(e *Evidence) { e.Application.PostProbeLogicalDigest = other },
		"post-probe-catalog-drift":       func(e *Evidence) { e.Application.PostProbeCatalogDigest = other },
		"missing-class":                  func(e *Evidence) { e.Classes = e.Classes[1:] },
		"extra-class":                    func(e *Evidence) { e.Classes = append(e.Classes, e.Classes[0]) },
		"combined-checksum-substitution": func(e *Evidence) { e.Classes[4].Source = other; e.Classes[4].Recovered = other },
		"combined-count-substitution":    func(e *Evidence) { e.Classes[1].SourceRows++; e.Classes[1].RecoveredRows++ },
		"combined-count-overflow":        func(e *Evidence) { e.Classes[1].SourceRows = math.MaxInt64; e.Classes[1].RecoveredRows = math.MaxInt64 },
		"quiet-window-overflow":          func(e *Evidence) { e.Cleanup.TwoSweepQuietWindowSeconds = math.MaxInt64 },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			value := validPostgreSQLRecoveryEvidence()
			change(&value)
			rejectRecoveryEvidence(t, value)
		})
	}
	for index := 0; index < reflect.TypeOf(RecoveryAccessBinding{}).NumField(); index++ {
		name := reflect.TypeOf(RecoveryAccessBinding{}).Field(index).Name
		t.Run("observed-binding/"+name, func(t *testing.T) {
			e := validPostgreSQLRecoveryEvidence()
			reflect.ValueOf(&e.RecoveryAccess.Observed).Elem().FieldByName(name).SetString(other)
			rejectRecoveryEvidence(t, e)
		})
	}
}

func TestEvidenceV2RequiresEveryProbeAndDataClass(t *testing.T) {
	for index, operation := range applicationAllowOrder {
		for _, mutation := range []string{"operation", "principal", "rows", "values"} {
			t.Run("allow/"+operation+"/"+mutation, func(t *testing.T) {
				e := validPostgreSQLRecoveryEvidence()
				probe := &e.Application.Allowed[index]
				switch mutation {
				case "operation":
					probe.Operation = "unverified"
				case "principal":
					probe.PrincipalIdentity = e.Catalog.OwnerIdentity
				case "rows":
					probe.AffectedRows = 0
				case "values":
					probe.ValuesMatched = false
				}
				rejectRecoveryEvidence(t, e)
			})
		}
	}
	for index, operation := range applicationDenyOrder {
		for _, mutation := range []string{"operation", "principal", "sqlstate"} {
			t.Run("deny/"+operation+"/"+mutation, func(t *testing.T) {
				e := validPostgreSQLRecoveryEvidence()
				probe := &e.Application.Denied[index]
				switch mutation {
				case "operation":
					probe.Operation = "unverified"
				case "principal":
					probe.PrincipalIdentity = e.Catalog.OwnerIdentity
				case "sqlstate":
					probe.SQLState = "25P02"
				}
				rejectRecoveryEvidence(t, e)
			})
		}
	}
	for index, name := range logicalClassOrder {
		for _, mutation := range []string{"name", "digest", "bytes", "rows", "matched"} {
			t.Run("class/"+name+"/"+mutation, func(t *testing.T) {
				e := validPostgreSQLRecoveryEvidence()
				class := &e.Classes[index]
				switch mutation {
				case "name":
					class.DataClass = "unverified"
				case "digest":
					class.Recovered = syntheticRecoveryIdentity("different")
				case "bytes":
					class.RecoveredBytes++
				case "rows":
					class.RecoveredRows++
				case "matched":
					class.Matched = false
				}
				rejectRecoveryEvidence(t, e)
			})
		}
	}
}

func TestEvidenceV2RejectsChronologyAndMalformedFacts(t *testing.T) {
	tests := map[string]func(*Evidence){
		"marker-before-snapshot":                 func(e *Evidence) { e.Consistency.MarkerCreatedAt = "2026-07-23T00:02:59Z" },
		"qualification-before-marker":            func(e *Evidence) { e.Consistency.QualifiedAt = "2026-07-23T00:03:09Z" },
		"archive-before-qualification":           func(e *Evidence) { e.Consistency.ArchiveVerifiedAt = e.Checksum.SourceCapturedAt },
		"read-before-archive":                    func(e *Evidence) { e.RecoveryAccess.VerifiedAt = e.Checksum.SourceCapturedAt },
		"read-after-recovery-start":              func(e *Evidence) { e.RecoveryAccess.VerifiedAt = e.Recovery.ReadyAt },
		"target-before-ready":                    func(e *Evidence) { e.Consistency.RecoveredTargetVerifiedAt = e.Recovery.StartedAt },
		"target-after-checksum":                  func(e *Evidence) { e.Consistency.RecoveredTargetVerifiedAt = e.Recovery.ValidatedAt },
		"probe-before-checksum":                  func(e *Evidence) { e.Application.StartedAt = e.Recovery.ReadyAt },
		"probe-completion-before-start":          func(e *Evidence) { e.Application.CompletedAt = e.Recovery.ReadyAt },
		"post-probe-before-rollback":             func(e *Evidence) { e.Application.PostProbeCapturedAt = e.Application.StartedAt },
		"post-probe-after-validation":            func(e *Evidence) { e.Application.PostProbeCapturedAt = e.Cleanup.StartedAt },
		"access-expired":                         func(e *Evidence) { e.RecoveryAccess.ExpiresAt = e.Recovery.ValidatedAt },
		"credential-expired":                     func(e *Evidence) { e.RecoveryAccess.CredentialExpiresAt = &e.Recovery.ValidatedAt },
		"credential-expiry-malformed":            func(e *Evidence) { value := "unknown"; e.RecoveryAccess.CredentialExpiresAt = &value },
		"catalog-source-different-snapshot-time": func(e *Evidence) { e.Catalog.SourceCapturedAt = e.BaseBackup.CompletedAt },
		"catalog-recovered-after-probe":          func(e *Evidence) { e.Catalog.RecoveredCapturedAt = e.Application.CompletedAt },
		"replay-before-marker":                   func(e *Evidence) { e.WALArchive.ReplayedThrough = e.Checksum.SourceCapturedAt },
		"malformed-boundary-digest":              func(e *Evidence) { e.Consistency.BoundaryDigest = "raw-marker-or-secret" },
		"malformed-timestamp":                    func(e *Evidence) { e.Application.CompletedAt = "not-a-time" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			value := validPostgreSQLRecoveryEvidence()
			change(&value)
			rejectRecoveryEvidence(t, value)
		})
	}
	e := validPostgreSQLRecoveryEvidence()
	e.RecoveryAccess.CredentialExpiresAt = &e.ExpiresAt
	if VerifyEvidence(bytes.NewReader(marshalPostgreSQLRecoveryEvidence(t, e))) != nil {
		t.Fatal("explicit unexpired temporary credential was rejected")
	}
	e.Consistency.BoundaryDigest = "private-input-must-not-escape"
	if err := VerifyEvidence(bytes.NewReader(marshalPostgreSQLRecoveryEvidence(t, e))); err == nil || strings.Contains(err.Error(), "private-input") {
		t.Fatal("invalid evidence was accepted or reflected private input")
	}
}

func replaceRecoveryEvidenceField(t *testing.T, payload []byte, path []any, replacement any) []byte {
	t.Helper()
	var document any
	if json.Unmarshal(payload, &document) != nil {
		t.Fatal("decode synthetic fixture")
	}
	current := document
	for _, segment := range path[:len(path)-1] {
		switch value := segment.(type) {
		case string:
			current = current.(map[string]any)[value]
		case int:
			current = current.([]any)[value]
		}
	}
	current.(map[string]any)[path[len(path)-1].(string)] = replacement
	changed, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}
