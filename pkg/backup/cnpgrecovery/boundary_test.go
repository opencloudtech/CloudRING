// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package cnpgrecovery

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func boundaryFixture() (BoundarySnapshot, BoundaryMarker) {
	source := BoundarySource{SystemIdentifier: "7612345678912345678", Timeline: 1, WALSegmentBytes: 16 << 20, ServerStartedAt: "2026-09-07T09:00:00Z"}
	return BoundarySnapshot{Source: source, Snapshot: "4294967300:4294967300:", Isolation: "repeatable read", ReadOnly: true},
		BoundaryMarker{SourceBefore: source, SourceAfter: source, Name: "recovery_synthetic_01", LSN: "0/30000A0", WALFile: "000000010000000000000003", FirstXID: "4294967300"}
}

func TestBoundaryRequiresAllocationFenceRatherThanEmptyOrEqualSnapshots(t *testing.T) {
	for name, change := range map[string]func(*BoundarySnapshot, *BoundaryMarker){
		"writer-committed-between-capture-and-marker":     func(s *BoundarySnapshot, m *BoundaryMarker) { m.FirstXID = "4294967301" },
		"newer-active-writer-omitted-from-empty-snapshot": func(s *BoundarySnapshot, m *BoundaryMarker) { m.FirstXID = "4294967301" },
		"writer-changed-data-then-changed-it-back":        func(s *BoundarySnapshot, m *BoundaryMarker) { m.FirstXID = "4294967302" },
		"older-active-writer":                             func(s *BoundarySnapshot, m *BoundaryMarker) { s.Snapshot = "4294967299:4294967300:4294967299" },
		"older-prepared-writer":                           func(s *BoundarySnapshot, m *BoundaryMarker) { s.Snapshot = "4294967299:4294967300:4294967299" },
		"wrong-allocation-order":                          func(s *BoundarySnapshot, m *BoundaryMarker) { m.FirstXID = "4294967299" },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot, marker := boundaryFixture()
			change(&snapshot, &marker)
			if _, err := QualifyBoundary(snapshot, marker); !errors.Is(err, ErrConsistentBoundaryUnavailable) {
				t.Fatalf("concurrent boundary did not return inconclusive: %v", err)
			}
		})
	}
	snapshot, marker := boundaryFixture()
	qualified, err := QualifyBoundary(snapshot, marker)
	if err != nil {
		t.Fatal(err)
	}
	if digest, err := BoundarySHA256(qualified); err != nil || len(digest) != 64 {
		t.Fatal("qualified boundary lacks a digest")
	}
	// A later writer is allowed. There is deliberately no 'latest snapshot'
	// equality guard that would invalidate an already qualified WAL marker.
	marker.FirstXID = "4294967301"
	if digest, err := BoundarySHA256(QualifiedBoundary{SchemaVersion: BoundarySchemaVersion, Snapshot: snapshot, Marker: marker}); err == nil || digest != "" {
		t.Fatal("unqualified boundary received a digest")
	}
}

func TestBoundaryRejectsMissingIdentityAndMalformedFullXIDs(t *testing.T) {
	xid := "4294967300"
	for name, change := range map[string]func(*BoundarySnapshot, *BoundaryMarker){
		"source-read-write":                 func(s *BoundarySnapshot, m *BoundaryMarker) { s.ReadOnly = false },
		"source-read-committed":             func(s *BoundarySnapshot, m *BoundaryMarker) { s.Isolation = "read committed" },
		"source-assigned-xid":               func(s *BoundarySnapshot, m *BoundaryMarker) { s.AssignedXID = &xid },
		"marker-preassigned-xid":            func(s *BoundarySnapshot, m *BoundaryMarker) { m.XIDBefore = &xid },
		"marker-assigned-before-allocation": func(s *BoundarySnapshot, m *BoundaryMarker) { m.XIDAfter = &xid },
		"source-system-changed":             func(s *BoundarySnapshot, m *BoundaryMarker) { m.SourceAfter.SystemIdentifier = "7612345678912345679" },
		"source-restarted":                  func(s *BoundarySnapshot, m *BoundaryMarker) { m.SourceAfter.ServerStartedAt = "2026-09-07T09:00:01Z" },
		"source-promoted":                   func(s *BoundarySnapshot, m *BoundaryMarker) { m.SourceAfter.Timeline = 2 },
		"source-standby": func(s *BoundarySnapshot, m *BoundaryMarker) {
			s.Source.InRecovery = true
			m.SourceBefore = s.Source
			m.SourceAfter = s.Source
		},
		"invalid-source-timestamp": func(s *BoundarySnapshot, m *BoundaryMarker) {
			s.Source.ServerStartedAt = strings.Repeat("a", 25)
			m.SourceBefore = s.Source
			m.SourceAfter = s.Source
		},
		"wrong-wal-timeline":    func(s *BoundarySnapshot, m *BoundaryMarker) { m.WALFile = "000000020000000000000003" },
		"wrong-wal-segment":     func(s *BoundarySnapshot, m *BoundaryMarker) { m.WALFile = "000000010000000000000004" },
		"invalid-wal":           func(s *BoundarySnapshot, m *BoundaryMarker) { m.WALFile = strings.Repeat("G", 24) },
		"invalid-lsn":           func(s *BoundarySnapshot, m *BoundaryMarker) { m.LSN = "0/100000000" },
		"zero-lsn":              func(s *BoundarySnapshot, m *BoundaryMarker) { m.LSN = "0/0" },
		"marker-sql-injection":  func(s *BoundarySnapshot, m *BoundaryMarker) { m.Name = "point'); SELECT 1;--" },
		"overflow-xid":          func(s *BoundarySnapshot, m *BoundaryMarker) { m.FirstXID = "18446744073709551616" },
		"special-xid":           func(s *BoundarySnapshot, m *BoundaryMarker) { m.FirstXID = "4294967297" },
		"snapshot-leading-zero": func(s *BoundarySnapshot, m *BoundaryMarker) { s.Snapshot = "04294967300:4294967300:" },
		"snapshot-empty":        func(s *BoundarySnapshot, m *BoundaryMarker) { s.Snapshot = "" },
		"snapshot-overflow": func(s *BoundarySnapshot, m *BoundaryMarker) {
			s.Snapshot = "18446744073709551616:18446744073709551616:"
		},
		"snapshot-active-outside-range": func(s *BoundarySnapshot, m *BoundaryMarker) { s.Snapshot = "4294967300:4294967301:4294967301" },
		"snapshot-active-duplicate": func(s *BoundarySnapshot, m *BoundaryMarker) {
			s.Snapshot = "4294967300:4294967302:4294967300,4294967300"
		},
	} {
		t.Run(name, func(t *testing.T) {
			snapshot, marker := boundaryFixture()
			change(&snapshot, &marker)
			if _, err := QualifyBoundary(snapshot, marker); err == nil || errors.Is(err, ErrConsistentBoundaryUnavailable) {
				t.Fatal("malformed evidence was not rejected as invalid")
			}
		})
	}
}

func TestBoundaryDecodersRequireExplicitNullAndFalseFacts(t *testing.T) {
	snapshot, marker := boundaryFixture()
	payload, _ := json.Marshal(snapshot)
	if _, err := DecodeBoundarySnapshot(payload); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"assignedXid", "readOnly", "isolation", "source", "snapshot"} {
		var object map[string]any
		_ = json.Unmarshal(payload, &object)
		delete(object, field)
		changed, _ := json.Marshal(object)
		if _, err := DecodeBoundarySnapshot(changed); err == nil {
			t.Fatalf("omitted %s was accepted", field)
		}
	}
	changed := strings.Replace(string(payload), `"inRecovery":false`, `"inRecovery":null`, 1)
	if _, err := DecodeBoundarySnapshot([]byte(changed)); err == nil {
		t.Fatal("null standby fact became false")
	}
	status, _ := json.Marshal(map[string]any{"source": marker.SourceBefore, "assignedXid": nil})
	point, _ := json.Marshal(map[string]any{"name": marker.Name, "lsn": marker.LSN, "walFile": marker.WALFile})
	rows := [][]byte{status, point, status, []byte(marker.FirstXID)}
	decoded, err := DecodeBoundaryMarker(rows)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := QualifyBoundary(snapshot, decoded); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][][]byte{rows[:3], {point, status, status, rows[3]}, {status, point, status, []byte(marker.FirstXID + "\n")}} {
		if _, err := DecodeBoundaryMarker(bad); err == nil {
			t.Fatal("incomplete or reordered marker rows were accepted")
		}
	}
}

func TestMarkerSQLKeepsAllocationAfterSeparateNoXIDObservations(t *testing.T) {
	for _, name := range []string{"", "point'; select 1", strings.Repeat("a", 64), "point-with-hyphen"} {
		if _, err := MarkerSQL(name); err == nil {
			t.Fatal("unsafe restore marker name was accepted")
		}
	}
	statements, err := MarkerSQL("point_synthetic")
	if err != nil || len(statements) != 6 || statements[0] != "BEGIN READ WRITE" || statements[5] != "COMMIT" {
		t.Fatal("marker transaction order is incomplete")
	}
	for i, statement := range statements {
		if strings.Contains(statement, "pg_current_xact_id()") != (i == 4) {
			t.Fatal("XID allocation escaped its ordered statement")
		}
		if strings.Contains(statement, "pg_create_restore_point(") != (i == 2) {
			t.Fatal("restore point escaped its ordered statement")
		}
	}
	if !strings.Contains(statements[1], "pg_current_xact_id_if_assigned()") || !strings.Contains(statements[3], "pg_current_xact_id_if_assigned()") || !strings.Contains(statements[2], "pg_walfile_name(lsn - 1)") {
		t.Fatal("marker no-XID or exact-WAL observations are missing")
	}
}

func TestBoundaryUsesSegmentContainingRecordEnd(t *testing.T) {
	for _, test := range []struct{ lsn, file string }{
		{"0/2000000", "000000010000000000000001"},
		{"0/2000001", "000000010000000000000002"},
		{"1/0", "0000000100000000000000FF"},
		{"1/1", "000000010000000100000000"},
	} {
		t.Run(test.lsn, func(t *testing.T) {
			snapshot, marker := boundaryFixture()
			marker.LSN, marker.WALFile = test.lsn, test.file
			if _, err := QualifyBoundary(snapshot, marker); err != nil {
				t.Fatal("containing WAL segment was rejected")
			}
			marker.WALFile = "000000010000000000000003"
			if _, err := QualifyBoundary(snapshot, marker); err == nil {
				t.Fatal("unrelated WAL segment was accepted")
			}
		})
	}
}
