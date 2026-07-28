// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

// Package drill implements the provider-neutral Goal01 backup/restore drill
// transaction. Provider and cluster mutations are available only through the
// content-pinned adapter protocol declared here.
package drill

const (
	PlanSchemaVersion      = "cloudring.backup-drill.plan/v1"
	ApprovalSchemaVersion  = "cloudring.backup-drill.approval/v1"
	AdapterRequestVersion  = "cloudring.backup-drill.adapter-request/v1"
	AdapterResponseVersion = "cloudring.backup-drill.adapter-response/v1"
	JournalEntryVersion    = "cloudring.backup-drill.journal-entry/v1"
	ReceiptSchemaVersion   = "cloudring.backup-drill.execution-receipt/v1"
	AdapterProtocolVersion = "cloudring.backup-drill.adapter/v1"
	ApprovalTuplePrefix    = "goal01-backup-restore"
)

var TargetKinds = []string{"Etcd", "VirtualMachineClaim", "Volume", "Namespace", "KubernetesClusterClaim"}

var ApplySteps = []string{
	"approval-consumed", "mutation-started", "etcd-offcell-complete", "velero-backup-complete",
	"restore-watch-create-observe-complete", "etcd-sandbox-restored", "restore-validation-complete",
	"cleanup-ready", "isolated-targets-deleted", "residual-sweep-1", "residual-sweep-2",
	"proof-assembled", "completed",
}

type ObjectIdentity struct {
	Kind        string `json:"kind"`
	Namespace   string `json:"namespace,omitempty"`
	Name        string `json:"name"`
	ScopeSHA256 string `json:"scopeSha256"`
}

type IsolatedNamespace struct {
	RestoreIndex       int            `json:"restoreIndex"`
	RestoreName        string         `json:"restoreName"`
	RestoreScopeSHA256 string         `json:"restoreScopeSha256"`
	SourceNamespace    string         `json:"sourceNamespace"`
	Destination        ObjectIdentity `json:"destination"`
}

type StorageLocation struct {
	Name      string `json:"name"`
	UIDSHA256 string `json:"uidSha256"`
	// Generation is the value observed when the plan is issued. It is audit
	// context, not a universal desired-state fence: some provider CRDs update
	// status through the main resource and legitimately advance generation.
	// Adapters must bind live continuity with UIDSHA256 plus ConfigSHA256.
	Generation   int64  `json:"generation"`
	ConfigSHA256 string `json:"configSha256"`
}

type ObjectStore struct {
	Prefix               string `json:"prefix"`
	MinimumRetentionDays int    `json:"minimumRetentionDays"`
	ObjectLockMode       string `json:"objectLockMode"`
}

type Baseline struct {
	Kind           string `json:"kind"`
	IdentitySHA256 string `json:"identitySha256"`
	StateSHA256    string `json:"stateSha256"`
	DataSHA256     string `json:"dataSha256"`
}

type ExecutableIdentity struct {
	Name             string `json:"name"`
	ExecutableSHA256 string `json:"executableSha256"`
}

type CleanupTarget struct {
	Kind                       string `json:"kind"`
	Namespace                  string `json:"namespace,omitempty"`
	Name                       string `json:"name"`
	PreconditionIdentitySHA256 string `json:"preconditionIdentitySha256"`
}

type Plan struct {
	SchemaVersion           string              `json:"schemaVersion"`
	OperationID             string              `json:"operationId"`
	ProofID                 string              `json:"proofId"`
	InstallationID          string              `json:"installationId"`
	AcceptedPublicSHA       string              `json:"acceptedPublicSha"`
	AcceptedDownstreamSHA   string              `json:"acceptedDownstreamSha"`
	ClusterIdentitySHA256   string              `json:"clusterIdentitySha256"`
	BackupStorageLocation   StorageLocation     `json:"backupStorageLocation"`
	ObjectStore             ObjectStore         `json:"objectStore"`
	SourceBaselines         []Baseline          `json:"sourceBaselines"`
	Tool                    ExecutableIdentity  `json:"tool"`
	Adapter                 ExecutableIdentity  `json:"adapter"`
	Backup                  ObjectIdentity      `json:"backup"`
	Restores                []ObjectIdentity    `json:"restores"`
	IsolatedNamespaces      []IsolatedNamespace `json:"isolatedNamespaces"`
	EtcdSandbox             ObjectIdentity      `json:"etcdSandbox"`
	CleanupTargets          []CleanupTarget     `json:"cleanupTargets"`
	AggregateProofPathToken string              `json:"aggregateProofPathToken"`
	IssuedAt                string              `json:"issuedAt"`
	ExpiresAt               string              `json:"expiresAt"`
	RunNonceSHA256          string              `json:"runNonceSha256"`
}

type ApprovalReport struct {
	SchemaVersion           string `json:"schemaVersion"`
	OperationID             string `json:"operationId"`
	PlanSHA256              string `json:"planSha256"`
	ApprovalScopeSHA256     string `json:"approvalScopeSha256"`
	AdapterExecutableSHA256 string `json:"adapterExecutableSha256"`
	IssuedAt                string `json:"issuedAt"`
	ExpiresAt               string `json:"expiresAt"`
	ApprovalTuple           string `json:"approvalTuple"`
	PreflightRequestSHA256  string `json:"preflightRequestSha256"`
	PreflightResponseSHA256 string `json:"preflightResponseSha256"`
	PreflightEvidenceRef    string `json:"preflightEvidenceRef"`
	PreflightEvidenceSHA256 string `json:"preflightEvidenceSha256"`
	PreflightBindingSHA256  string `json:"preflightBindingSha256"`
	ReportSHA256            string `json:"reportSha256"`
}

type AdapterRequest struct {
	SchemaVersion           string          `json:"schemaVersion"`
	ProtocolVersion         string          `json:"protocolVersion"`
	OperationID             string          `json:"operationId"`
	PlanSHA256              string          `json:"planSha256"`
	ApprovalSHA256          string          `json:"approvalSha256,omitempty"`
	ApprovalScopeSHA256     string          `json:"approvalScopeSha256"`
	AdapterExecutableSHA256 string          `json:"adapterExecutableSha256"`
	Mode                    string          `json:"mode"`
	Step                    string          `json:"step"`
	PreviousJournalSHA256   string          `json:"previousJournalSha256,omitempty"`
	RequestID               string          `json:"requestId"`
	Plan                    Plan            `json:"plan"`
	RetainKinds             []string        `json:"retainKinds,omitempty"`
	CleanupTargets          []CleanupTarget `json:"cleanupTargets,omitempty"`
	RequestSHA256           string          `json:"requestSha256"`
}

type TargetResult struct {
	Kind                   string `json:"kind"`
	SourceChecksumSHA256   string `json:"sourceChecksumSha256"`
	RestoredChecksumSHA256 string `json:"restoredChecksumSha256"`
	EvidenceRef            string `json:"evidenceRef"`
	EvidenceSHA256         string `json:"evidenceSha256"`
}

type Evidence struct {
	Ref    string `json:"ref"`
	SHA256 string `json:"sha256"`
}

type RestoreObservation struct {
	RestoreName            string `json:"restoreName"`
	RestoreScopeSHA256     string `json:"restoreScopeSha256"`
	SourceNamespace        string `json:"sourceNamespace"`
	DestinationNamespace   string `json:"destinationNamespace"`
	DestinationScopeSHA256 string `json:"destinationScopeSha256"`
	EvidenceRef            string `json:"evidenceRef"`
	EvidenceSHA256         string `json:"evidenceSha256"`
}

type AdapterResponse struct {
	SchemaVersion                       string               `json:"schemaVersion"`
	ProtocolVersion                     string               `json:"protocolVersion"`
	OperationID                         string               `json:"operationId"`
	Step                                string               `json:"step"`
	RequestSHA256                       string               `json:"requestSha256"`
	AdapterExecutableSHA256             string               `json:"adapterExecutableSha256"`
	Status                              string               `json:"status"`
	Mutated                             bool                 `json:"mutated"`
	Evidence                            Evidence             `json:"evidence"`
	RestoreObservations                 []RestoreObservation `json:"restoreObservations,omitempty"`
	Targets                             []TargetResult       `json:"targets,omitempty"`
	IsolationEvidence                   *Evidence            `json:"isolationEvidence,omitempty"`
	CleanupEvidence                     *Evidence            `json:"cleanupEvidence,omitempty"`
	ObjectLockDeleteDenialReceiptSHA256 string               `json:"objectLockDeleteDenialReceiptSha256,omitempty"`
	AggregateProofArtifactSHA256        string               `json:"aggregateProofArtifactSha256,omitempty"`
	AggregateProofPathToken             string               `json:"aggregateProofPathToken,omitempty"`
	ResponseSHA256                      string               `json:"responseSha256"`
}

type JournalEntry struct {
	SchemaVersion           string           `json:"schemaVersion"`
	Sequence                int              `json:"sequence"`
	OperationID             string           `json:"operationId"`
	PlanSHA256              string           `json:"planSha256"`
	ApprovalSHA256          string           `json:"approvalSha256"`
	ApprovalScopeSHA256     string           `json:"approvalScopeSha256"`
	AdapterExecutableSHA256 string           `json:"adapterExecutableSha256"`
	Step                    string           `json:"step"`
	RequestSHA256           string           `json:"requestSha256"`
	ResponseSHA256          string           `json:"responseSha256"`
	Response                *AdapterResponse `json:"response,omitempty"`
	PreviousEntrySHA256     string           `json:"previousEntrySha256,omitempty"`
	RecordedAt              string           `json:"recordedAt"`
	EntrySHA256             string           `json:"entrySha256"`
}

type ExecutionReceipt struct {
	SchemaVersion                       string         `json:"schemaVersion"`
	OperationID                         string         `json:"operationId"`
	ProofID                             string         `json:"proofId"`
	InstallationID                      string         `json:"installationId"`
	PlanSHA256                          string         `json:"planSha256"`
	ApprovalSHA256                      string         `json:"approvalSha256"`
	ApprovalScopeSHA256                 string         `json:"approvalScopeSha256"`
	AdapterExecutableSHA256             string         `json:"adapterExecutableSha256"`
	Status                              string         `json:"status"`
	CompletedAt                         string         `json:"completedAt"`
	JournalHeadSHA256                   string         `json:"journalHeadSha256"`
	ExecutionEvidenceResponseSHA256     string         `json:"executionEvidenceResponseSha256"`
	Targets                             []TargetResult `json:"targets"`
	IsolationEvidence                   Evidence       `json:"isolationEvidence"`
	CleanupEvidence                     Evidence       `json:"cleanupEvidence"`
	ObjectLockDeleteDenialReceiptSHA256 string         `json:"objectLockDeleteDenialReceiptSha256"`
	AggregateProofArtifactSHA256        string         `json:"aggregateProofArtifactSha256"`
	AggregateProofPathToken             string         `json:"aggregateProofPathToken"`
	ReceiptSHA256                       string         `json:"receiptSha256"`
}
