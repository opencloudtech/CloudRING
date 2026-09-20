// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

// Package cnpgrecovery defines and verifies the provider-neutral evidence
// contract for an isolated CloudNativePG recovery from an off-cell base backup
// and continuous WAL archive.
package cnpgrecovery

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"regexp"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const EvidenceSchemaVersion = "cloudring.postgresql-cnpg-offcell-recovery-evidence/v2"

var (
	postgresqlRecoveryDigestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	postgresqlRecoveryRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	postgresqlRecoveryEvidenceInvalid = errors.New("PostgreSQL recovery evidence is invalid")
)

type Evidence struct {
	SchemaVersion  string                  `json:"schemaVersion"`
	SourceRevision string                  `json:"sourceRevision"`
	CollectedAt    string                  `json:"collectedAt"`
	ExpiresAt      string                  `json:"expiresAt"`
	OffCell        OffCellEvidence         `json:"offCell"`
	BaseBackup     BaseBackupEvidence      `json:"baseBackup"`
	WALArchive     WALArchiveEvidence      `json:"walArchive"`
	Recovery       RecoveryClusterEvidence `json:"recovery"`
	Checksum       ChecksumEvidence        `json:"checksum"`
	Consistency    ConsistencyEvidence     `json:"consistency"`
	RecoveryAccess RecoveryAccessEvidence  `json:"recoveryAccess"`
	Catalog        CatalogEvidence         `json:"catalog"`
	Application    ApplicationEvidence     `json:"application"`
	Classes        []LogicalClassEvidence  `json:"classes"`
	Cleanup        CleanupEvidence         `json:"cleanup"`
	Redaction      RedactionEvidence       `json:"redaction"`
	Verdict        string                  `json:"verdict"`
}

type OffCellEvidence struct {
	ObservedAt            string `json:"observedAt"`
	DestinationIdentity   string `json:"destinationIdentity"`
	FailureDomainDistinct bool   `json:"failureDomainDistinct"`
	RetentionDays         int    `json:"retentionDays"`
	ObjectLockMode        string `json:"objectLockMode"`
	ObjectLockMinimumDays int    `json:"objectLockMinimumDays"`
	ControlDeleteDenied   bool   `json:"controlDeleteDenied"`
}

type BaseBackupEvidence struct {
	Identity              string `json:"identity"`
	StartedAt             string `json:"startedAt"`
	CompletedAt           string `json:"completedAt"`
	Status                string `json:"status"`
	Bytes                 int64  `json:"bytes"`
	ObjectInventoryDigest string `json:"objectInventoryDigest"`
}

type WALArchiveEvidence struct {
	FirstRecoverabilityPoint string  `json:"firstRecoverabilityPoint"`
	LastArchivedAt           string  `json:"lastArchivedAt"`
	LastFailedAt             *string `json:"lastFailedAt"`
	ReplayedThrough          string  `json:"replayedThrough"`
	Continuous               bool    `json:"continuous"`
}

type RecoveryClusterEvidence struct {
	NamespaceIdentity    string `json:"namespaceIdentity"`
	ClusterIdentity      string `json:"clusterIdentity"`
	SourceIdentity       string `json:"sourceIdentity"`
	StartedAt            string `json:"startedAt"`
	ReadyAt              string `json:"readyAt"`
	ValidatedAt          string `json:"validatedAt"`
	ReadyInstances       int    `json:"readyInstances"`
	ExpectedInstances    int    `json:"expectedInstances"`
	ProductionRouteCount int    `json:"productionRouteCount"`
	WriteProbePassed     bool   `json:"writeProbePassed"`
}

type ChecksumEvidence struct {
	Algorithm             string `json:"algorithm"`
	ProjectionVersion     string `json:"projectionVersion"`
	Source                string `json:"source"`
	Recovered             string `json:"recovered"`
	SourceCapturedAt      string `json:"sourceCapturedAt"`
	RecoveredCapturedAt   string `json:"recoveredCapturedAt"`
	SourceLogicalBytes    int64  `json:"sourceLogicalBytes"`
	RecoveredLogicalBytes int64  `json:"recoveredLogicalBytes"`
	SourceRowCount        int64  `json:"sourceRowCount"`
	RecoveredRowCount     int64  `json:"recoveredRowCount"`
	Matched               bool   `json:"matched"`
}

type CleanupEvidence struct {
	StartedAt                  string                 `json:"startedAt"`
	CompletedAt                string                 `json:"completedAt"`
	Complete                   bool                   `json:"complete"`
	TwoSweepQuietWindowSeconds int                    `json:"twoSweepQuietWindowSeconds"`
	Sweeps                     []CleanupSweepEvidence `json:"sweeps"`
}

type CleanupSweepEvidence struct {
	ObservedAt                 string `json:"observedAt"`
	InventoryDigest            string `json:"inventoryDigest"`
	RecoveryNamespaceCount     int    `json:"recoveryNamespaceCount"`
	ClusterCount               int    `json:"clusterCount"`
	CredentialSecretCount      int    `json:"accessObjectCount"`
	PersistentVolumeClaimCount int    `json:"persistentVolumeClaimCount"`
	ServiceCount               int    `json:"serviceCount"`
	RouteCount                 int    `json:"routeCount"`
}

type RedactionEvidence struct {
	ContainsCredentials bool   `json:"containsCredentials"`
	ContainsEndpoints   bool   `json:"containsEndpoints"`
	ContainsTenantData  bool   `json:"containsTenantData"`
	Verdict             string `json:"verdict"`
}

// VerifyEvidence validates one sanitized v2 evidence instance. Historical v1
// receipts cannot satisfy this strengthened recovery contract. A successful
// result proves only that the supplied receipt satisfies this contract; callers
// must still bind the receipt to the accepted source revision and live run.
func VerifyEvidence(reader io.Reader) error {
	return verifyEvidence(reader, "")
}

// VerifyEvidenceForRevision validates one sanitized evidence instance and
// requires its source revision to match the accepted public-core commit.
func VerifyEvidenceForRevision(reader io.Reader, acceptedPublicSHA string) error {
	if !postgresqlRecoveryRevisionPattern.MatchString(acceptedPublicSHA) {
		return postgresqlRecoveryEvidenceInvalid
	}
	return verifyEvidence(reader, acceptedPublicSHA)
}

func verifyEvidence(reader io.Reader, acceptedPublicSHA string) error {
	payload, err := strictjson.Read(reader)
	if err != nil {
		return postgresqlRecoveryEvidenceInvalid
	}
	var evidence Evidence
	if !exactPostgreSQLRecoveryEvidenceShape(payload) ||
		strictjson.DecodeExact(payload, &evidence) != nil ||
		validatePostgreSQLRecoveryEvidence(evidence) != nil {
		return postgresqlRecoveryEvidenceInvalid
	}
	if acceptedPublicSHA != "" && evidence.SourceRevision != acceptedPublicSHA {
		return postgresqlRecoveryEvidenceInvalid
	}
	return nil
}

// Compare the typed round trip so omitted/null denial or zero-count facts
// cannot acquire their Go zero values. Strict decoding also rejects duplicate,
// unknown and case-substituted fields. The two explicitly nullable timestamps
// retain their actual JSON null representation.
func exactPostgreSQLRecoveryEvidenceShape(payload []byte) bool {
	var evidence Evidence
	if strictjson.DecodeExact(payload, &evidence) != nil {
		return false
	}
	canonical, err := json.Marshal(evidence)
	if err != nil {
		return false
	}
	var received, expected any
	return strictjson.Decode(payload, &received) == nil && strictjson.Decode(canonical, &expected) == nil && reflect.DeepEqual(received, expected)
}

func validatePostgreSQLRecoveryEvidence(evidence Evidence) error {
	if evidence.SchemaVersion != EvidenceSchemaVersion ||
		!postgresqlRecoveryRevisionPattern.MatchString(evidence.SourceRevision) ||
		evidence.Verdict != "pass" ||
		!validPostgreSQLRecoveryDigest(evidence.OffCell.DestinationIdentity) ||
		!evidence.OffCell.FailureDomainDistinct || evidence.OffCell.RetentionDays < 30 ||
		(evidence.OffCell.ObjectLockMode != "governance" && evidence.OffCell.ObjectLockMode != "compliance") ||
		evidence.OffCell.ObjectLockMinimumDays < 30 || !evidence.OffCell.ControlDeleteDenied ||
		!validPostgreSQLRecoveryDigest(evidence.BaseBackup.Identity) ||
		!validPostgreSQLRecoveryDigest(evidence.BaseBackup.ObjectInventoryDigest) ||
		evidence.BaseBackup.Status != "completed" || evidence.BaseBackup.Bytes <= 0 ||
		evidence.WALArchive.LastFailedAt != nil || !evidence.WALArchive.Continuous ||
		!validPostgreSQLRecoveryDigest(evidence.Recovery.NamespaceIdentity) ||
		!validPostgreSQLRecoveryDigest(evidence.Recovery.ClusterIdentity) ||
		!validPostgreSQLRecoveryDigest(evidence.Recovery.SourceIdentity) ||
		evidence.Recovery.ReadyInstances != 1 || evidence.Recovery.ExpectedInstances != 1 ||
		evidence.Recovery.ProductionRouteCount != 0 || !evidence.Recovery.WriteProbePassed ||
		evidence.Checksum.Algorithm != "sha256" ||
		evidence.Checksum.ProjectionVersion != "cloudring-postgresql-logical-state/v1" ||
		!validPostgreSQLRecoveryDigest(evidence.Checksum.Source) ||
		evidence.Checksum.Source != evidence.Checksum.Recovered || !evidence.Checksum.Matched ||
		evidence.Checksum.SourceLogicalBytes <= 0 ||
		evidence.Checksum.SourceLogicalBytes != evidence.Checksum.RecoveredLogicalBytes ||
		evidence.Checksum.SourceRowCount <= 0 ||
		evidence.Checksum.SourceRowCount != evidence.Checksum.RecoveredRowCount ||
		!evidence.Cleanup.Complete || evidence.Cleanup.TwoSweepQuietWindowSeconds < 30 ||
		len(evidence.Cleanup.Sweeps) != 2 ||
		evidence.Redaction.ContainsCredentials || evidence.Redaction.ContainsEndpoints ||
		evidence.Redaction.ContainsTenantData || evidence.Redaction.Verdict != "pass" {
		return postgresqlRecoveryEvidenceInvalid
	}
	for _, sweep := range evidence.Cleanup.Sweeps {
		if !validPostgreSQLRecoveryDigest(sweep.InventoryDigest) ||
			sweep.RecoveryNamespaceCount != 0 || sweep.ClusterCount != 0 ||
			sweep.CredentialSecretCount != 0 || sweep.PersistentVolumeClaimCount != 0 ||
			sweep.ServiceCount != 0 || sweep.RouteCount != 0 {
			return postgresqlRecoveryEvidenceInvalid
		}
	}
	if err := validatePostgreSQLRecoveryChronology(evidence); err != nil {
		return err
	}
	return validatePostgreSQLRecoveryAssurance(evidence)
}

func validatePostgreSQLRecoveryChronology(evidence Evidence) error {
	values := []string{
		evidence.OffCell.ObservedAt,
		evidence.BaseBackup.StartedAt,
		evidence.BaseBackup.CompletedAt,
		evidence.WALArchive.FirstRecoverabilityPoint,
		evidence.WALArchive.LastArchivedAt,
		evidence.WALArchive.ReplayedThrough,
		evidence.Recovery.StartedAt,
		evidence.Recovery.ReadyAt,
		evidence.Recovery.ValidatedAt,
		evidence.Checksum.SourceCapturedAt,
		evidence.Checksum.RecoveredCapturedAt,
		evidence.Cleanup.StartedAt,
		evidence.Cleanup.Sweeps[0].ObservedAt,
		evidence.Cleanup.Sweeps[1].ObservedAt,
		evidence.Cleanup.CompletedAt,
		evidence.CollectedAt,
		evidence.ExpiresAt,
	}
	parsed := make([]time.Time, len(values))
	for index, value := range values {
		instant, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return postgresqlRecoveryEvidenceInvalid
		}
		parsed[index] = instant
	}
	offCellObserved, backupStarted, backupCompleted := parsed[0], parsed[1], parsed[2]
	firstRecoverable, lastArchived, replayedThrough := parsed[3], parsed[4], parsed[5]
	recoveryStarted, recoveryReady, recoveryValidated := parsed[6], parsed[7], parsed[8]
	sourceCaptured, recoveredCaptured := parsed[9], parsed[10]
	cleanupStarted, firstSweep, secondSweep, cleanupCompleted := parsed[11], parsed[12], parsed[13], parsed[14]
	collected, expires := parsed[15], parsed[16]
	if int64(evidence.Cleanup.TwoSweepQuietWindowSeconds) > math.MaxInt64/int64(time.Second) {
		return postgresqlRecoveryEvidenceInvalid
	}
	quietWindow := time.Duration(evidence.Cleanup.TwoSweepQuietWindowSeconds) * time.Second
	if offCellObserved.After(backupStarted) || !backupStarted.Before(backupCompleted) ||
		firstRecoverable.After(backupCompleted) || sourceCaptured.Before(backupCompleted) ||
		lastArchived.Before(sourceCaptured) || replayedThrough.Before(sourceCaptured) ||
		!lastArchived.Before(recoveryStarted) || !recoveryStarted.Before(recoveryReady) ||
		recoveredCaptured.Before(recoveryReady) || recoveredCaptured.After(recoveryValidated) ||
		replayedThrough.After(recoveredCaptured) ||
		recoveryValidated.Before(recoveryReady) || !recoveryValidated.Before(cleanupStarted) ||
		firstSweep.Before(cleanupStarted) || secondSweep.Sub(firstSweep) < quietWindow ||
		!secondSweep.Before(cleanupCompleted) || !cleanupCompleted.Before(collected) ||
		!collected.Before(expires) {
		return postgresqlRecoveryEvidenceInvalid
	}
	return nil
}

func validPostgreSQLRecoveryDigest(value string) bool {
	return postgresqlRecoveryDigestPattern.MatchString(value)
}
