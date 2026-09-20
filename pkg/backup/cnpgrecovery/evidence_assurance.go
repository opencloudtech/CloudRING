// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package cnpgrecovery

const ConsistencyMethod = "postgresql-post-marker-first-xid/v1"

// ConsistencyEvidence reports the required acquisition facts without exposing
// raw XIDs, LSNs, marker names, database identifiers or Kubernetes identities.
// BoundaryDigest is the prefixed digest of a successfully qualified boundary;
// it supplements, and does not replace, the explicit qualification facts.
type ConsistencyEvidence struct {
	Method                       string `json:"method"`
	BoundaryDigest               string `json:"boundaryDigest"`
	SourceIdentity               string `json:"sourceIdentity"`
	PrimaryIdentity              string `json:"primaryIdentity"`
	SnapshotIdentity             string `json:"snapshotIdentity"`
	SnapshotIsolation            string `json:"snapshotIsolation"`
	SnapshotReadOnly             bool   `json:"snapshotReadOnly"`
	SnapshotXIDAssigned          bool   `json:"snapshotXidAssigned"`
	SnapshotBoundsEqual          bool   `json:"snapshotBoundsEqual"`
	SnapshotActiveXIDCount       int    `json:"snapshotActiveXidCount"`
	LogicalCatalogSameSnapshot   bool   `json:"logicalCatalogSameSnapshot"`
	MarkerIdentity               string `json:"markerIdentity"`
	MarkerLSNIdentity            string `json:"markerLsnIdentity"`
	MarkerWALIdentity            string `json:"markerWalIdentity"`
	MarkerNameUnique             bool   `json:"markerNameUnique"`
	MarkerXIDBeforeAssigned      bool   `json:"markerXidBeforeAssigned"`
	MarkerXIDAfterAssigned       bool   `json:"markerXidAfterAssigned"`
	MarkerStatementsOrdered      bool   `json:"markerStatementsOrdered"`
	MarkerSameTransaction        bool   `json:"markerSameTransaction"`
	MarkerCommitConfirmed        bool   `json:"markerCommitConfirmed"`
	FirstXIDMatchesSnapshot      bool   `json:"firstXidMatchesSnapshot"`
	SourceIdentityUnchanged      bool   `json:"sourceIdentityUnchanged"`
	MarkerCreatedAt              string `json:"markerCreatedAt"`
	QualifiedAt                  string `json:"qualifiedAt"`
	ArchiveVerifiedAt            string `json:"archiveVerifiedAt"`
	ArchivedMarkerWALIdentity    string `json:"archivedMarkerWalIdentity"`
	ArchiveObjectIdentity        string `json:"archiveObjectIdentity"`
	ExactMarkerArchived          bool   `json:"exactMarkerArchived"`
	BaseBackupPrecedesMarker     bool   `json:"baseBackupPrecedesMarker"`
	RecoveredMarkerIdentity      string `json:"recoveredMarkerIdentity"`
	RecoveredLSNIdentity         string `json:"recoveredLsnIdentity"`
	RecoveredTargetVerifiedAt    string `json:"recoveredTargetVerifiedAt"`
	ExactRecoveredTargetVerified bool   `json:"exactRecoveredTargetVerified"`
}

// RecoveryAccessBinding binds the approved inputs to their independent
// pre-projection readback. Values identify metadata and scope, never credentials.
// SecretIdentity and SecretVersionIdentity identify the Kubernetes Secret object
// and its metadata version; their JSON names distinguish objects from values.
type RecoveryAccessBinding struct {
	PrincipalIdentity      string `json:"principalIdentity"`
	PolicyIdentity         string `json:"policyIdentity"`
	PolicyRevisionIdentity string `json:"policyRevisionIdentity"`
	SecretIdentity         string `json:"objectIdentity"`
	SecretVersionIdentity  string `json:"objectVersionIdentity"`
	DestinationIdentity    string `json:"destinationIdentity"`
	ScopeIdentity          string `json:"scopeIdentity"`
}

// RecoveryAccessEvidence requires effective provider-policy evidence and reads
// of the selected base backup and exact marker WAL object. Object Lock denial
// alone cannot establish this principal's write/delete restrictions.
type RecoveryAccessEvidence struct {
	Expected                  RecoveryAccessBinding `json:"expected"`
	Observed                  RecoveryAccessBinding `json:"observed"`
	WriterPrincipalIdentity   string                `json:"writerPrincipalIdentity"`
	VerifiedAt                string                `json:"verifiedAt"`
	ExpiresAt                 string                `json:"expiresAt"`
	CredentialExpiresAt       *string               `json:"credentialExpiresAt"`
	CredentialExpiryChecked   bool                  `json:"expiryChecked"`
	IndependentPolicyVerified bool                  `json:"independentPolicyVerified"`
	RequiredReadPermissions   bool                  `json:"requiredReadPermissions"`
	WriteDenied               bool                  `json:"writeDenied"`
	DeleteDenied              bool                  `json:"deleteDenied"`
	AdministrationDenied      bool                  `json:"administrationDenied"`
	OutsideScopeDenied        bool                  `json:"outsideScopeDenied"`
	BaseBackupIdentity        string                `json:"baseBackupIdentity"`
	MarkerWALIdentity         string                `json:"markerWalIdentity"`
	BaseBackupReadPassed      bool                  `json:"baseBackupReadPassed"`
	MarkerWALReadPassed       bool                  `json:"markerWalReadPassed"`
	AllowlistedProjectionOnly bool                  `json:"allowlistedProjectionOnly"`
	SourceBindingUnchanged    bool                  `json:"sourceBindingUnchanged"`
}

// CatalogEvidence contains qualified catalog digests from the logical source
// snapshot and the restored pre-probe snapshot, with explicit role separation.
type CatalogEvidence struct {
	ContractVersion        string `json:"contractVersion"`
	OwnerIdentity          string `json:"ownerIdentity"`
	ApplicationIdentity    string `json:"applicationIdentity"`
	SourceSnapshotIdentity string `json:"sourceSnapshotIdentity"`
	Source                 string `json:"source"`
	Recovered              string `json:"recovered"`
	SourceCapturedAt       string `json:"sourceCapturedAt"`
	RecoveredCapturedAt    string `json:"recoveredCapturedAt"`
	SourceContractValid    bool   `json:"sourceContractValid"`
	RecoveredContractValid bool   `json:"recoveredContractValid"`
}

type ApplicationAllowEvidence struct {
	Operation         string `json:"operation"`
	PrincipalIdentity string `json:"principalIdentity"`
	AffectedRows      int64  `json:"affectedRows"`
	ValuesMatched     bool   `json:"valuesMatched"`
}

type ApplicationDenyEvidence struct {
	Operation         string `json:"operation"`
	PrincipalIdentity string `json:"principalIdentity"`
	SQLState          string `json:"sqlState"`
}

// ApplicationEvidence requires an actual application connection, operation-
// specific allows and insufficient_privilege denials, then verified rollback.
type ApplicationEvidence struct {
	PrincipalIdentity      string                     `json:"principalIdentity"`
	StartedAt              string                     `json:"startedAt"`
	CompletedAt            string                     `json:"completedAt"`
	Authenticated          bool                       `json:"authenticated"`
	IdentityVerified       bool                       `json:"identityVerified"`
	Allowed                []ApplicationAllowEvidence `json:"allowed"`
	Denied                 []ApplicationDenyEvidence  `json:"denied"`
	RolledBack             bool                       `json:"rolledBack"`
	ResidualDocumentRows   int64                      `json:"residualDocumentRows"`
	ResidualAuditRows      int64                      `json:"residualAuditRows"`
	PostProbeCapturedAt    string                     `json:"postProbeCapturedAt"`
	PostProbeLogicalDigest string                     `json:"postProbeLogicalDigest"`
	PostProbeCatalogDigest string                     `json:"postProbeCatalogDigest"`
}

type LogicalClassEvidence struct {
	DataClass      string `json:"dataClass"`
	Source         string `json:"source"`
	Recovered      string `json:"recovered"`
	SourceBytes    int64  `json:"sourceBytes"`
	RecoveredBytes int64  `json:"recoveredBytes"`
	SourceRows     int64  `json:"sourceRows"`
	RecoveredRows  int64  `json:"recoveredRows"`
	Matched        bool   `json:"matched"`
}
