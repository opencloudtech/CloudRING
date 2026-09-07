// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package cnpgrecovery

import (
	"math"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/transactionalstate"
)

var logicalClassOrder = [...]string{"portal-state", "orders", "support-tickets", "audit-events", "postgresql-cnpg"}
var applicationAllowOrder = [...]string{"documents-insert", "documents-read", "documents-update-cas", "documents-delete", "audit-insert", "audit-read"}
var applicationDenyOrder = [...]string{"audit-update", "audit-delete", "schema-create", "migration-read", "migration-write", "document-truncate", "document-maintenance", "role-escalation"}

func validatePostgreSQLRecoveryAssurance(e Evidence) error {
	c := e.Consistency
	if c.Method != ConsistencyMethod || !validRecoveryDigests(c.BoundaryDigest, c.SourceIdentity, c.PrimaryIdentity, c.SnapshotIdentity,
		c.MarkerIdentity, c.MarkerLSNIdentity, c.MarkerWALIdentity, c.ArchiveObjectIdentity) ||
		c.SourceIdentity != e.Recovery.SourceIdentity || c.SnapshotIsolation != "repeatable read" || !c.SnapshotReadOnly ||
		c.SnapshotXIDAssigned || !c.SnapshotBoundsEqual || c.SnapshotActiveXIDCount != 0 || !c.LogicalCatalogSameSnapshot ||
		!c.MarkerNameUnique || c.MarkerXIDBeforeAssigned || c.MarkerXIDAfterAssigned || !c.MarkerStatementsOrdered ||
		!c.MarkerSameTransaction || !c.MarkerCommitConfirmed || !c.FirstXIDMatchesSnapshot || !c.SourceIdentityUnchanged ||
		!c.ExactMarkerArchived || c.ArchivedMarkerWALIdentity != c.MarkerWALIdentity || !c.BaseBackupPrecedesMarker ||
		!c.ExactRecoveredTargetVerified || c.RecoveredMarkerIdentity != c.MarkerIdentity || c.RecoveredLSNIdentity != c.MarkerLSNIdentity {
		return postgresqlRecoveryEvidenceInvalid
	}
	a := e.RecoveryAccess
	if a.Expected != a.Observed || !validRecoveryDigests(a.Expected.PrincipalIdentity, a.Expected.PolicyIdentity,
		a.Expected.PolicyRevisionIdentity, a.Expected.SecretIdentity, a.Expected.SecretVersionIdentity,
		a.Expected.DestinationIdentity, a.Expected.ScopeIdentity, a.WriterPrincipalIdentity) ||
		a.Expected.PrincipalIdentity == a.WriterPrincipalIdentity || a.Expected.DestinationIdentity != e.OffCell.DestinationIdentity ||
		!a.CredentialExpiryChecked || !a.IndependentPolicyVerified || !a.RequiredReadPermissions ||
		!a.WriteDenied || !a.DeleteDenied || !a.AdministrationDenied || !a.OutsideScopeDenied ||
		a.BaseBackupIdentity != e.BaseBackup.Identity || a.MarkerWALIdentity != c.MarkerWALIdentity ||
		!a.BaseBackupReadPassed || !a.MarkerWALReadPassed || !a.AllowlistedProjectionOnly || !a.SourceBindingUnchanged {
		return postgresqlRecoveryEvidenceInvalid
	}
	catalog := e.Catalog
	if catalog.ContractVersion != transactionalstate.RecoveryContractSchemaVersion ||
		!validRecoveryDigests(catalog.OwnerIdentity, catalog.ApplicationIdentity, catalog.Source) ||
		catalog.OwnerIdentity == catalog.ApplicationIdentity || catalog.SourceSnapshotIdentity != c.SnapshotIdentity ||
		catalog.Source != catalog.Recovered || !catalog.SourceContractValid || !catalog.RecoveredContractValid {
		return postgresqlRecoveryEvidenceInvalid
	}
	app := e.Application
	if app.PrincipalIdentity != catalog.ApplicationIdentity || !app.Authenticated || !app.IdentityVerified ||
		len(app.Allowed) != len(applicationAllowOrder) || len(app.Denied) != len(applicationDenyOrder) ||
		!app.RolledBack || app.ResidualDocumentRows != 0 || app.ResidualAuditRows != 0 ||
		app.PostProbeLogicalDigest != e.Checksum.Recovered || app.PostProbeCatalogDigest != catalog.Recovered {
		return postgresqlRecoveryEvidenceInvalid
	}
	for index, operation := range applicationAllowOrder {
		probe := app.Allowed[index]
		if probe.Operation != operation || probe.PrincipalIdentity != app.PrincipalIdentity || probe.AffectedRows != 1 || !probe.ValuesMatched {
			return postgresqlRecoveryEvidenceInvalid
		}
	}
	for index, operation := range applicationDenyOrder {
		probe := app.Denied[index]
		if probe.Operation != operation || probe.PrincipalIdentity != app.PrincipalIdentity || probe.SQLState != "42501" {
			return postgresqlRecoveryEvidenceInvalid
		}
	}
	if err := validateLogicalClasses(e); err != nil {
		return err
	}
	return validateRecoveryAssuranceChronology(e)
}

func validateLogicalClasses(e Evidence) error {
	if len(e.Classes) != len(logicalClassOrder) {
		return postgresqlRecoveryEvidenceInvalid
	}
	var detailRows int64
	for index, name := range logicalClassOrder {
		class := e.Classes[index]
		if class.DataClass != name || !validPostgreSQLRecoveryDigest(class.Source) || class.Source != class.Recovered ||
			class.SourceBytes <= 0 || class.SourceBytes != class.RecoveredBytes ||
			class.SourceRows < 0 || class.SourceRows != class.RecoveredRows || !class.Matched {
			return postgresqlRecoveryEvidenceInvalid
		}
		if index > 0 && index < len(logicalClassOrder)-1 {
			if class.SourceRows > math.MaxInt64-detailRows {
				return postgresqlRecoveryEvidenceInvalid
			}
			detailRows += class.SourceRows
		}
	}
	combined := e.Classes[len(e.Classes)-1]
	if e.Classes[0].SourceRows != 1 || combined.SourceRows != detailRows ||
		combined.Source != e.Checksum.Source || combined.Recovered != e.Checksum.Recovered ||
		combined.SourceBytes != e.Checksum.SourceLogicalBytes || combined.RecoveredBytes != e.Checksum.RecoveredLogicalBytes ||
		combined.SourceRows != e.Checksum.SourceRowCount || combined.RecoveredRows != e.Checksum.RecoveredRowCount {
		return postgresqlRecoveryEvidenceInvalid
	}
	return nil
}

func validateRecoveryAssuranceChronology(e Evidence) error {
	values := []string{
		e.Checksum.SourceCapturedAt, e.Consistency.MarkerCreatedAt, e.Consistency.QualifiedAt,
		e.Consistency.ArchiveVerifiedAt, e.WALArchive.LastArchivedAt, e.RecoveryAccess.VerifiedAt,
		e.Recovery.StartedAt, e.Recovery.ReadyAt, e.Consistency.RecoveredTargetVerifiedAt,
		e.Checksum.RecoveredCapturedAt, e.Application.StartedAt, e.Application.CompletedAt,
		e.Application.PostProbeCapturedAt, e.Recovery.ValidatedAt, e.RecoveryAccess.ExpiresAt,
		e.Catalog.SourceCapturedAt, e.Catalog.RecoveredCapturedAt, e.WALArchive.ReplayedThrough,
	}
	parsed := make([]time.Time, len(values))
	for index, value := range values {
		instant, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || instant.IsZero() {
			return postgresqlRecoveryEvidenceInvalid
		}
		parsed[index] = instant
	}
	source, marker, qualified, archived, lastArchived, access := parsed[0], parsed[1], parsed[2], parsed[3], parsed[4], parsed[5]
	started, ready, target, recovered, probeStarted, probeCompleted := parsed[6], parsed[7], parsed[8], parsed[9], parsed[10], parsed[11]
	postProbe, validated, accessExpires := parsed[12], parsed[13], parsed[14]
	if marker.Before(source) || qualified.Before(marker) || archived.Before(qualified) || lastArchived.Before(marker) ||
		archived.Before(lastArchived) || access.Before(archived) || access.After(started) ||
		target.Before(ready) || target.After(recovered) || probeStarted.Before(recovered) ||
		probeCompleted.Before(probeStarted) || postProbe.Before(probeCompleted) || postProbe.After(validated) ||
		!accessExpires.After(validated) || !parsed[15].Equal(source) || !parsed[16].Equal(recovered) || parsed[17].Before(marker) {
		return postgresqlRecoveryEvidenceInvalid
	}
	if expires := e.RecoveryAccess.CredentialExpiresAt; expires != nil {
		instant, err := time.Parse(time.RFC3339Nano, *expires)
		if err != nil || !instant.After(validated) {
			return postgresqlRecoveryEvidenceInvalid
		}
	}
	return nil
}

func validRecoveryDigests(values ...string) bool {
	for _, value := range values {
		if !validPostgreSQLRecoveryDigest(value) {
			return false
		}
	}
	return true
}
