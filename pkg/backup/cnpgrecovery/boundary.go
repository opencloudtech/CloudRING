// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package cnpgrecovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const BoundarySchemaVersion = "cloudring.postgresql-snapshot-boundary/v1"

// ErrConsistentBoundaryUnavailable identifies an ordinary concurrency result,
// not corruption. Callers may retry with a fresh snapshot and unique marker,
// under an explicit attempt/time budget. They must not pause application writes
// or restore to a marker from an unqualified attempt.
var ErrConsistentBoundaryUnavailable = errors.New("consistent PostgreSQL boundary is unavailable")

var restoreMarkerNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// BoundarySource is collected from the same bound primary connection before
// and after the marker. An orchestration caller must additionally bind the
// cluster and primary process/container identities; database metadata alone
// does not establish a Kubernetes Pod or provider identity.
type BoundarySource struct {
	SystemIdentifier string `json:"systemIdentifier"`
	Timeline         uint32 `json:"timeline"`
	WALSegmentBytes  uint32 `json:"walSegmentBytes"`
	ServerStartedAt  string `json:"serverStartedAt"`
	InRecovery       bool   `json:"inRecovery"`
}

// BoundarySnapshot must be captured in the same repeatable-read, read-only
// transaction as every protected logical and catalog projection. AssignedXID
// is null only when pg_current_xact_id_if_assigned() returned SQL NULL.
type BoundarySnapshot struct {
	Source      BoundarySource `json:"source"`
	Snapshot    string         `json:"snapshot"`
	Isolation   string         `json:"isolation"`
	ReadOnly    bool           `json:"readOnly"`
	AssignedXID *string        `json:"assignedXid"`
}

// BoundaryMarker represents the ordered statements returned by MarkerSQL.
// FirstXID must be allocated after the named WAL marker and both no-XID
// observations, in that same fresh marker transaction. Equal before/after
// logical hashes do not substitute for this allocation fence.
type BoundaryMarker struct {
	SourceBefore BoundarySource `json:"sourceBefore"`
	SourceAfter  BoundarySource `json:"sourceAfter"`
	Name         string         `json:"name"`
	LSN          string         `json:"lsn"`
	WALFile      string         `json:"walFile"`
	XIDBefore    *string        `json:"xidBefore"`
	XIDAfter     *string        `json:"xidAfter"`
	FirstXID     string         `json:"firstXid"`
}

type QualifiedBoundary struct {
	SchemaVersion string           `json:"schemaVersion"`
	Snapshot      BoundarySnapshot `json:"snapshot"`
	Marker        BoundaryMarker   `json:"marker"`
}

// DecodeBoundarySnapshot requires every acquisition field, including explicit
// false and SQL-null facts. Missing source metadata or an omitted assignedXid
// must not be interpreted as evidence of no assigned transaction.
func DecodeBoundarySnapshot(payload []byte) (BoundarySnapshot, error) {
	var snapshot BoundarySnapshot
	if decodeBoundaryObservation(payload, &snapshot) != nil {
		return BoundarySnapshot{}, errors.New("PostgreSQL boundary snapshot is incomplete")
	}
	return snapshot, nil
}

// DecodeBoundaryMarker accepts the four SELECT rows from a fully completed
// MarkerSQL transaction, in order. The final row is the plain full-XID string.
// The caller must reject failed or uncertain COMMIT independently.
func DecodeBoundaryMarker(rows [][]byte) (BoundaryMarker, error) {
	invalid := errors.New("PostgreSQL boundary marker is incomplete")
	if len(rows) != 4 {
		return BoundaryMarker{}, invalid
	}
	type status struct {
		Source      BoundarySource `json:"source"`
		AssignedXID *string        `json:"assignedXid"`
	}
	var before, after status
	var point struct {
		Name    string `json:"name"`
		LSN     string `json:"lsn"`
		WALFile string `json:"walFile"`
	}
	if decodeBoundaryObservation(rows[0], &before) != nil || decodeBoundaryObservation(rows[1], &point) != nil || decodeBoundaryObservation(rows[2], &after) != nil {
		return BoundaryMarker{}, invalid
	}
	first := string(rows[3])
	if _, ok := parseFullXID(first); !ok {
		return BoundaryMarker{}, invalid
	}
	return BoundaryMarker{SourceBefore: before.Source, SourceAfter: after.Source, Name: point.Name, LSN: point.LSN, WALFile: point.WALFile, XIDBefore: before.AssignedXID, XIDAfter: after.AssignedXID, FirstXID: first}, nil
}

func decodeBoundaryObservation(payload []byte, destination any) error {
	invalid := errors.New("PostgreSQL boundary observation is invalid")
	if len(payload) > 2<<20 || strictjson.DecodeExact(payload, destination) != nil {
		return invalid
	}
	canonical, err := json.Marshal(destination)
	var received, expected any
	if err != nil || strictjson.Decode(payload, &received) != nil || strictjson.Decode(canonical, &expected) != nil || !reflect.DeepEqual(received, expected) {
		return invalid
	}
	return nil
}

// QualifyBoundary accepts only an empty source snapshot xmin=xmax=N followed
// by the marker transaction's first allocation F=N. PostgreSQL allocates full
// XIDs sequentially across the cluster: any writer allocated after the source
// snapshot but before this allocation makes F>N, including a writer in another
// database and an active newer XID omitted from the snapshot's in-progress list.
// A source transaction still in progress below N prevents xmin=xmax. The
// predicate therefore binds the logged transactional projection to the marker
// without rejecting application DML. It does not cover nontransactional state.
//
// This validates observations, not their acquisition. Callers must enforce the
// SQL ordering, same-session marker transaction, primary identity and complete
// response, then separately verify base-backup chronology, exact marker WAL
// archival, physical recovery, application access and cleanup.
func QualifyBoundary(snapshot BoundarySnapshot, marker BoundaryMarker) (QualifiedBoundary, error) {
	if !validBoundarySource(snapshot.Source) || snapshot.Source != marker.SourceBefore || snapshot.Source != marker.SourceAfter || snapshot.Isolation != "repeatable read" || !snapshot.ReadOnly || snapshot.AssignedXID != nil {
		return QualifiedBoundary{}, errors.New("PostgreSQL boundary source observation is invalid")
	}
	minimum, maximum, active, err := parseBoundarySnapshot(snapshot.Snapshot)
	if err != nil {
		return QualifiedBoundary{}, err
	}
	first, ok := parseFullXID(marker.FirstXID)
	if !ok || !restoreMarkerNamePattern.MatchString(marker.Name) || !validMarkerLSN(marker.LSN) || !validMarkerWAL(marker.WALFile, marker.LSN, snapshot.Source) || marker.XIDBefore != nil || marker.XIDAfter != nil {
		return QualifiedBoundary{}, errors.New("PostgreSQL restore marker observation is invalid")
	}
	if minimum != maximum || len(active) != 0 || first != maximum {
		return QualifiedBoundary{}, ErrConsistentBoundaryUnavailable
	}
	return QualifiedBoundary{SchemaVersion: BoundarySchemaVersion, Snapshot: snapshot, Marker: marker}, nil
}

func BoundarySHA256(boundary QualifiedBoundary) (string, error) {
	if boundary.SchemaVersion != BoundarySchemaVersion {
		return "", errors.New("PostgreSQL boundary schema is invalid")
	}
	if _, err := QualifyBoundary(boundary.Snapshot, boundary.Marker); err != nil {
		return "", err
	}
	payload, err := json.Marshal(boundary)
	if err != nil {
		return "", errors.New("encode PostgreSQL boundary")
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func parseBoundarySnapshot(value string) (uint64, uint64, []uint64, error) {
	invalid := errors.New("PostgreSQL full-XID snapshot is invalid")
	if len(value) > 1<<20 {
		return 0, 0, nil, invalid
	}
	parts := strings.Split(value, ":")
	if len(parts) != 3 {
		return 0, 0, nil, invalid
	}
	minimum, minOK := parseFullXID(parts[0])
	maximum, maxOK := parseFullXID(parts[1])
	if !minOK || !maxOK || minimum > maximum {
		return 0, 0, nil, invalid
	}
	var active []uint64
	if parts[2] != "" {
		for _, item := range strings.Split(parts[2], ",") {
			xid, ok := parseFullXID(item)
			if !ok || xid < minimum || xid >= maximum || (len(active) != 0 && xid <= active[len(active)-1]) {
				return 0, 0, nil, invalid
			}
			active = append(active, xid)
		}
	}
	return minimum, maximum, active, nil
}

func parseFullXID(value string) (uint64, bool) {
	xid, err := strconv.ParseUint(value, 10, 64)
	return xid, err == nil && xid >= 3 && xid&0xffffffff >= 3 && strconv.FormatUint(xid, 10) == value
}

func validBoundarySource(source BoundarySource) bool {
	system, err := strconv.ParseUint(source.SystemIdentifier, 10, 64)
	started, timeErr := time.Parse(time.RFC3339Nano, source.ServerStartedAt)
	segment := source.WALSegmentBytes
	return err == nil && system > 0 && strconv.FormatUint(system, 10) == source.SystemIdentifier && source.Timeline > 0 && segment >= 1<<20 && segment <= 1<<30 && segment&(segment-1) == 0 && timeErr == nil && !started.IsZero() && strings.HasSuffix(source.ServerStartedAt, "Z") && !source.InRecovery
}

func validMarkerLSN(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || strings.ToUpper(value) != value {
		return false
	}
	var nonzero bool
	for _, part := range parts {
		if len(part) < 1 || len(part) > 8 {
			return false
		}
		n, err := strconv.ParseUint(part, 16, 32)
		if err != nil || strings.ToUpper(strconv.FormatUint(n, 16)) != part {
			return false
		}
		nonzero = nonzero || n != 0
	}
	return nonzero
}

func validMarkerWAL(value, lsn string, source BoundarySource) bool {
	if len(value) != 24 || strings.ToUpper(value) != value {
		return false
	}
	if _, err := hex.DecodeString(value); err != nil {
		return false
	}
	parts := strings.Split(lsn, "/")
	if len(parts) != 2 || source.WALSegmentBytes == 0 {
		return false
	}
	high, highErr := strconv.ParseUint(parts[0], 16, 32)
	low, lowErr := strconv.ParseUint(parts[1], 16, 32)
	if highErr != nil || lowErr != nil {
		return false
	}
	end := (high << 32) | low
	if end == 0 {
		return false
	}
	// A restore point returns its record's end LSN. At an exact segment
	// boundary its last byte belongs to the preceding segment.
	segment := (end - 1) / uint64(source.WALSegmentBytes)
	perLog := uint64(1<<32) / uint64(source.WALSegmentBytes)
	return value == fmt.Sprintf("%08X%08X%08X", source.Timeline, segment/perLog, segment%perLog)
}
