// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

// Package restoreproof defines provider-neutral, source-safe backup and restore
// evidence contracts. It does not contain installation credentials or provider
// implementation details.
package restoreproof

const (
	ReceiptSchemaVersion      = "cloudring.restore-proof.csi-data-mover/v1"
	BaselineSchemaVersion     = "cloudring.restore-proof.source-baseline/v1"
	VeleroVersion             = "v1.18.2"
	MethodCSIDataMover        = "csi-data-mover"
	ScopeSingleVolumeDataPath = "single-volume-data-path-only"
)

var (
	CoreV1PVCGVR = GVR{Version: "v1", Resource: "persistentvolumeclaims"}
	CoreV1PVGVR  = GVR{Version: "v1", Resource: "persistentvolumes"}
	CoreV1CMGVR  = GVR{Version: "v1", Resource: "configmaps"}

	VeleroV1BackupGVR              = GVR{Group: "velero.io", Version: "v1", Resource: "backups"}
	VeleroV1RestoreGVR             = GVR{Group: "velero.io", Version: "v1", Resource: "restores"}
	VeleroV1ServerStatusRequestGVR = GVR{Group: "velero.io", Version: "v1", Resource: "serverstatusrequests"}
	DataUploadGVR                  = GVR{Group: "velero.io", Version: "v2alpha1", Resource: "datauploads"}
	DataDownloadGVR                = GVR{Group: "velero.io", Version: "v2alpha1", Resource: "datadownloads"}
)

// GVR identifies the exact Kubernetes API endpoint used for an observation.
type GVR struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

// TargetResource records a restored object while raw UIDs and resource
// versions remain outside the receipt.
type TargetResource struct {
	Resource              string `json:"resource"`
	Namespace             string `json:"namespace"`
	Name                  string `json:"name"`
	UIDSHA256             string `json:"uidSha256"`
	ResourceVersionSHA256 string `json:"resourceVersionSha256"`
	ValidatedStateSHA256  string `json:"validatedStateSha256"`
}

// SourceResource proves that a source object's identity and proof-relevant
// state did not change across a restore. Resource versions may differ when an
// unrelated metadata or controller bookkeeping write occurred.
type SourceResource struct {
	Resource                    string `json:"resource"`
	Namespace                   string `json:"namespace"`
	Name                        string `json:"name"`
	UIDSHA256                   string `json:"uidSha256"`
	ResourceVersionBeforeSHA256 string `json:"resourceVersionBeforeSha256"`
	ResourceVersionAfterSHA256  string `json:"resourceVersionAfterSha256"`
	StateBeforeSHA256           string `json:"stateBeforeSha256"`
	StateAfterSHA256            string `json:"stateAfterSha256"`
}

// SourceBaseline is collected before a restore and compared again before the
// proof collector accepts source immutability.
type SourceBaseline struct {
	SchemaVersion  string         `json:"schemaVersion"`
	CapturedAt     string         `json:"capturedAt"`
	Source         SourceResource `json:"source"`
	EvidenceRef    string         `json:"evidenceRef"`
	EvidenceSHA256 string         `json:"evidenceSha256"`
}

// CleanupContext binds the proof to exact source and restored inventories and
// to the observed cleanup timeline.
type CleanupContext struct {
	ValidationCompletedAt      string           `json:"validationCompletedAt"`
	CleanupStartedAt           string           `json:"cleanupStartedAt"`
	CleanupCompletedAt         string           `json:"cleanupCompletedAt"`
	VerifiedAt                 string           `json:"verifiedAt"`
	TargetResources            []TargetResource `json:"targetResources"`
	VeleroAutoCleanedResources []TargetResource `json:"veleroAutoCleanedResources"`
	SourceResources            []SourceResource `json:"sourceResources"`
}

// VolumeRestoreContext is the minimum signed parent context required to
// validate one CSI data-mover volume receipt.
type VolumeRestoreContext struct {
	VeleroNamespace              string            `json:"veleroNamespace"`
	RestoreID                    string            `json:"restoreId"`
	RestoreUIDSHA256             string            `json:"restoreUidSha256"`
	RestoreResourceVersionSHA256 string            `json:"restoreResourceVersionSha256"`
	BackupID                     string            `json:"backupId"`
	BackupUIDSHA256              string            `json:"backupUidSha256"`
	BackupResourceVersionSHA256  string            `json:"backupResourceVersionSha256"`
	BackupStorageLocation        string            `json:"backupStorageLocation"`
	BackupCompletedAt            string            `json:"backupCompletedAt"`
	NamespaceMapping             map[string]string `json:"namespaceMapping"`
	RestoreStartedAt             string            `json:"restoreStartedAt"`
	CompletedAt                  string            `json:"completedAt"`
	CSISnapshotTimeout           string            `json:"csiSnapshotTimeout"`
	BackupUploaderConfigSHA256   string            `json:"backupUploaderConfigSha256,omitempty"`
	RestoreUploaderConfigSHA256  string            `json:"restoreUploaderConfigSha256,omitempty"`
	DataMoverConfigSHA256        string            `json:"dataMoverConfigSha256,omitempty"`
	SourceBaseline               SourceBaseline    `json:"sourceBaseline"`
	Cleanup                      CleanupContext    `json:"cleanup"`
}

// VeleroRuntimeAttestation binds the receipt to a fresh official
// ServerStatusRequest processed by the running Velero server.
type VeleroRuntimeAttestation struct {
	GVR            GVR             `json:"gvr"`
	Object         *TargetResource `json:"object"`
	ServerVersion  string          `json:"serverVersion"`
	Phase          string          `json:"phase"`
	ProcessedAt    string          `json:"processedAt"`
	ObservedAt     string          `json:"observedAt"`
	EvidenceRef    string          `json:"evidenceRef"`
	EvidenceSHA256 string          `json:"evidenceSha256"`
}

// DataLineage is byte-compatible with the enterprise Volume lineage object for
// this method-specific slice.
type DataLineage struct {
	Status                   string                   `json:"status"`
	Method                   string                   `json:"method"`
	Probes                   []DataProbe              `json:"probes"`
	ProbeSetSHA256           string                   `json:"probeSetSha256"`
	AggregateDataSHA256      string                   `json:"aggregateDataSha256"`
	ValidatedBytes           int64                    `json:"validatedBytes"`
	Helpers                  []AsyncHelper            `json:"helpers"`
	BackendArtifacts         []BackendArtifactLineage `json:"backendArtifacts"`
	ProviderAbsenceSetSHA256 string                   `json:"providerAbsenceSetSha256"`
	EvidenceRef              string                   `json:"evidenceRef"`
	EvidenceSHA256           string                   `json:"evidenceSha256"`
}

// DataProbe binds an independently measured content digest to exact source and
// restored PVC/PV objects.
type DataProbe struct {
	Status                       string          `json:"status"`
	Implementation               string          `json:"implementation"`
	Version                      string          `json:"version"`
	RequestSHA256                string          `json:"requestSha256"`
	AdapterExecutableSHA256      string          `json:"adapterExecutableSha256"`
	SourceGVR                    GVR             `json:"sourceGvr"`
	Source                       *SourceResource `json:"source"`
	TargetGVR                    GVR             `json:"targetGvr"`
	Target                       *TargetResource `json:"target"`
	TargetPV                     *TargetResource `json:"targetPv"`
	SourcePVCVolumeName          string          `json:"sourcePvcVolumeName"`
	TargetPVCVolumeName          string          `json:"targetPvcVolumeName"`
	HashAlgorithm                string          `json:"hashAlgorithm"`
	SourceDataSHA256             string          `json:"sourceDataSha256"`
	RestoredDataSHA256           string          `json:"restoredDataSha256"`
	ValidatedBytes               int64           `json:"validatedBytes"`
	StartedAt                    string          `json:"startedAt"`
	CompletedAt                  string          `json:"completedAt"`
	ObservedDurationMilliseconds int64           `json:"observedDurationMilliseconds"`
	EvidenceRef                  string          `json:"evidenceRef"`
	EvidenceSHA256               string          `json:"evidenceSha256"`
}

// AsyncHelper records the exact terminal DataDownload used by the restore.
type AsyncHelper struct {
	GVR                   GVR                  `json:"gvr"`
	Object                *TargetResource      `json:"object"`
	RestoreUIDSHA256      string               `json:"restoreUidSha256"`
	OwnerRestoreUIDSHA256 string               `json:"ownerRestoreUidSha256"`
	RestoreNameLabel      string               `json:"restoreNameLabel"`
	RestoreUIDLabelSHA256 string               `json:"restoreUidLabelSha256"`
	TerminalStatus        string               `json:"terminalStatus"`
	StartedAt             string               `json:"startedAt"`
	CompletedAt           string               `json:"completedAt"`
	BytesDone             int64                `json:"bytesDone"`
	TotalBytes            int64                `json:"totalBytes"`
	OperationIDSHA256     string               `json:"operationIdSha256"`
	TargetPVC             *TargetResource      `json:"targetPvc"`
	SourcePVC             *SourceResource      `json:"sourcePvc"`
	DataDownload          *DataDownloadLineage `json:"dataDownload"`
	EvidenceRef           string               `json:"evidenceRef"`
	EvidenceSHA256        string               `json:"evidenceSha256"`
}

// DataDownloadLineage records the Velero 1.18.2 fields derived from an exact
// archived DataUploadResult.
type DataDownloadLineage struct {
	TargetVolumePVC               string          `json:"targetVolumePvc"`
	TargetVolumePV                string          `json:"targetVolumePv"`
	TargetVolumeNamespace         string          `json:"targetVolumeNamespace"`
	TargetPV                      *TargetResource `json:"targetPv"`
	BackupStorageLocation         string          `json:"backupStorageLocation"`
	DataMover                     string          `json:"dataMover"`
	SnapshotIDSHA256              string          `json:"snapshotIdSha256"`
	SourceNamespace               string          `json:"sourceNamespace"`
	DataMoverConfigSHA256         string          `json:"dataMoverConfigSha256,omitempty"`
	Cancel                        bool            `json:"cancel"`
	OperationTimeout              string          `json:"operationTimeout"`
	NodeOS                        string          `json:"nodeOs"`
	SnapshotSize                  int64           `json:"snapshotSize"`
	AsyncOperationIDLabelSHA256   string          `json:"asyncOperationIdLabelSha256"`
	DataUploadResultObject        *TargetResource `json:"dataUploadResultObject"`
	DataUploadUIDSHA256           string          `json:"dataUploadUidSha256"`
	ArchivedDataUploadSHA256      string          `json:"archivedDataUploadSha256"`
	DataUploadResultPayloadSHA256 string          `json:"dataUploadResultPayloadSha256"`
}

// BackendArtifactLineage proves a provider handle was present for the exact PV
// and then absent twice after Kubernetes cleanup.
type BackendArtifactLineage struct {
	Status                     string                       `json:"status"`
	ProviderImplementation     string                       `json:"providerImplementation"`
	ProviderVersion            string                       `json:"providerVersion"`
	ArtifactHandleSHA256       string                       `json:"artifactHandleSha256"`
	SourceKind                 string                       `json:"sourceKind"`
	DerivedFrom                *TargetResource              `json:"derivedFrom"`
	TargetPVC                  *TargetResource              `json:"targetPvc"`
	TargetPV                   *TargetResource              `json:"targetPv"`
	SourcePV                   *SourceResource              `json:"sourcePv"`
	SourceArtifactHandleSHA256 string                       `json:"sourceArtifactHandleSha256"`
	LineageSHA256              string                       `json:"lineageSha256"`
	DeletedAt                  string                       `json:"deletedAt"`
	PresenceObservation        *ProviderObservation         `json:"presenceObservation"`
	AbsenceObservations        []ProviderAbsenceObservation `json:"absenceObservations"`
	SourcePresenceObservation  *ProviderObservation         `json:"sourcePresenceObservation"`
	EvidenceRef                string                       `json:"evidenceRef"`
	EvidenceSHA256             string                       `json:"evidenceSha256"`
}

// ProviderObservation binds one adapter response to a unique request and the
// pinned adapter executable used for the invocation.
type ProviderObservation struct {
	Status                  string `json:"status"`
	ArtifactHandleSHA256    string `json:"artifactHandleSha256"`
	ObservedAt              string `json:"observedAt"`
	RequestSHA256           string `json:"requestSha256"`
	AdapterExecutableSHA256 string `json:"adapterExecutableSha256"`
	QuerySHA256             string `json:"querySha256"`
	ObservationSHA256       string `json:"observationSha256"`
	EvidenceRef             string `json:"evidenceRef"`
	EvidenceSHA256          string `json:"evidenceSha256"`
}

type ProviderAbsenceObservation = ProviderObservation

// DataUploadProof is a typed binding of the retained live object and the
// corresponding object from the exact Velero Backup archive.
type DataUploadProof struct {
	GVR                           GVR             `json:"gvr"`
	Namespace                     string          `json:"namespace"`
	Name                          string          `json:"name"`
	UIDSHA256                     string          `json:"uidSha256"`
	ResourceVersionSHA256         string          `json:"resourceVersionSha256"`
	OwnerBackupUIDSHA256          string          `json:"ownerBackupUidSha256"`
	BackupNameLabel               string          `json:"backupNameLabel"`
	BackupUIDLabelSHA256          string          `json:"backupUidLabelSha256"`
	SourcePVCUIDLabelSHA256       string          `json:"sourcePvcUidLabelSha256"`
	SourcePVCGVR                  GVR             `json:"sourcePvcGvr"`
	SourcePVC                     *SourceResource `json:"sourcePvc"`
	SnapshotType                  string          `json:"snapshotType"`
	VolumeSnapshotSHA256          string          `json:"volumeSnapshotSha256"`
	StorageClassSHA256            string          `json:"storageClassSha256"`
	SnapshotClassSHA256           string          `json:"snapshotClassSha256,omitempty"`
	Driver                        string          `json:"driver"`
	BackupStorageLocation         string          `json:"backupStorageLocation"`
	DataMover                     string          `json:"dataMover"`
	DataMoverConfigSHA256         string          `json:"dataMoverConfigSha256,omitempty"`
	OperationIDSHA256             string          `json:"operationIdSha256"`
	OperationTimeout              string          `json:"operationTimeout"`
	Phase                         string          `json:"phase"`
	Message                       string          `json:"message"`
	StartedAt                     string          `json:"startedAt"`
	CompletedAt                   string          `json:"completedAt"`
	SnapshotIDSHA256              string          `json:"snapshotIdSha256"`
	NodeOS                        string          `json:"nodeOs"`
	DataMoverResultSHA256         string          `json:"dataMoverResultSha256,omitempty"`
	BytesDone                     int64           `json:"bytesDone"`
	TotalBytes                    int64           `json:"totalBytes"`
	ArchivedObjectSHA256          string          `json:"archivedObjectSha256"`
	RetainedAfterRestoreCleanupAt string          `json:"retainedAfterRestoreCleanupAt"`
	EvidenceRef                   string          `json:"evidenceRef"`
	EvidenceSHA256                string          `json:"evidenceSha256"`
}

type DataUploadResultProof struct {
	Status                   string          `json:"status"`
	GVR                      GVR             `json:"gvr"`
	Object                   *TargetResource `json:"object"`
	DataUploadUIDSHA256      string          `json:"dataUploadUidSha256"`
	DataUploadName           string          `json:"dataUploadName"`
	ArchivedDataUploadSHA256 string          `json:"archivedDataUploadSha256"`
	RestoreUIDSHA256         string          `json:"restoreUidSha256"`
	RestoreUIDLabelSHA256    string          `json:"restoreUidLabelSha256"`
	RestoreUIDDataKeySHA256  string          `json:"restoreUidDataKeySha256"`
	PVCNamespaceNameLabel    string          `json:"pvcNamespaceNameLabel"`
	ResourceUsage            string          `json:"resourceUsage"`
	SourcePVC                *SourceResource `json:"sourcePvc"`
	BackupStorageLocation    string          `json:"backupStorageLocation"`
	DataMover                string          `json:"dataMover"`
	SnapshotIDSHA256         string          `json:"snapshotIdSha256"`
	SourceNamespace          string          `json:"sourceNamespace"`
	SnapshotSize             int64           `json:"snapshotSize"`
	NodeOS                   string          `json:"nodeOs"`
	DataMoverResultSHA256    string          `json:"dataMoverResultSha256,omitempty"`
	ResultPayloadSHA256      string          `json:"resultPayloadSha256"`
	ObservedAt               string          `json:"observedAt"`
	VeleroAutoDeletedAt      string          `json:"veleroAutoDeletedAt"`
	EvidenceRef              string          `json:"evidenceRef"`
	EvidenceSHA256           string          `json:"evidenceSha256"`
}

// VolumeReceipt is the reusable unsigned receipt emitted by the collector.
// A downstream release process may sign it under its own trust policy.
type VolumeReceipt struct {
	SchemaVersion    string                   `json:"schemaVersion"`
	ProofScope       string                   `json:"proofScope"`
	VeleroVersion    string                   `json:"veleroVersion"`
	VeleroRuntime    VeleroRuntimeAttestation `json:"veleroRuntime"`
	CollectedAt      string                   `json:"collectedAt"`
	Context          VolumeRestoreContext     `json:"context"`
	Lineage          DataLineage              `json:"lineage"`
	DataUpload       DataUploadProof          `json:"dataUpload"`
	DataUploadResult DataUploadResultProof    `json:"dataUploadResult"`
	ReceiptSHA256    string                   `json:"receiptSha256"`
}
