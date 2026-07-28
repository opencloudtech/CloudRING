// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

// Package velero118 collects and decodes the exact Velero v1.18.2 CSI
// data-mover contract. Other Velero versions and restore methods fail closed.
package velero118

import (
	"context"
	"encoding/json"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
)

const (
	BaselineRequestSchemaVersion                    = "cloudring.restore-proof.baseline-request/v1"
	CollectionRequestSchemaVersion                  = "cloudring.restore-proof.collection-request/v1"
	AdapterRequestSchemaVersion                     = "cloudring.restore-proof.adapter-request/v2"
	AdapterResponseSchemaVersion                    = "cloudring.restore-proof.adapter-response/v2"
	CleanupReadySchemaVersion                       = "cloudring.restore-proof.cleanup-ready/v1"
	CleanupReadyStatus                              = "ready-for-cleanup"
	DataUploadResultObservationRequestSchemaVersion = "cloudring.restore-proof.data-upload-result-observation-request/v1"
	DataUploadResultObservationSchemaVersion        = "cloudring.restore-proof.data-upload-result-observation/v1"
	DataUploadResultObservationReadySchemaVersion   = "cloudring.restore-proof.data-upload-result-observation-ready/v1"
	DataUploadResultObservationReadyStatus          = "ready-for-restore"
)

type OwnerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller *bool  `json:"controller,omitempty"`
}

type Metadata struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	ResourceVersion   string            `json:"resourceVersion"`
	CreationTimestamp string            `json:"creationTimestamp"`
	DeletionTimestamp *string           `json:"deletionTimestamp,omitempty"`
	Labels            map[string]string `json:"labels"`
	OwnerReferences   []OwnerReference  `json:"ownerReferences"`
}

type Identity struct {
	Metadata         Metadata
	StateSHA256      string
	ProofStateSHA256 string
	Raw              map[string]any
}

func (identity Identity) Target(resource string) restoreproof.TargetResource {
	return restoreproof.TargetResource{
		Resource:              resource,
		Namespace:             identity.Metadata.Namespace,
		Name:                  identity.Metadata.Name,
		UIDSHA256:             restoreproof.SHA256(identity.Metadata.UID),
		ResourceVersionSHA256: restoreproof.SHA256(identity.Metadata.ResourceVersion),
		ValidatedStateSHA256:  identity.ProofStateSHA256,
	}
}

type Restore struct {
	Identity Identity
	Spec     RestoreSpec
	Status   RestoreStatus
}

type Backup struct {
	Identity Identity
	Spec     BackupSpec
	Status   BackupStatus
}

type ServerStatusRequest struct {
	Identity Identity
	Status   ServerStatusRequestStatus
}

type ServerStatusRequestStatus struct {
	Phase              string `json:"phase"`
	ProcessedTimestamp string `json:"processedTimestamp"`
	ServerVersion      string `json:"serverVersion"`
}

type PersistentVolumeClaim struct {
	Identity Identity
	Spec     PersistentVolumeClaimSpec
}

type PersistentVolumeClaimSpec struct {
	VolumeName       string  `json:"volumeName"`
	StorageClassName *string `json:"storageClassName"`
}

type PersistentVolume struct {
	Identity Identity
	Spec     PersistentVolumeSpec
}

type PersistentVolumeSpec struct {
	ClaimRef *ObjectReference `json:"claimRef"`
	CSI      *CSIVolumeSource `json:"csi"`
}

type ObjectReference struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

type CSIVolumeSource struct {
	Driver       string `json:"driver"`
	VolumeHandle string `json:"volumeHandle"`
}

type DataUpload struct {
	Identity Identity
	Spec     DataUploadSpec
	Status   DataUploadStatus
}

type CSISnapshot struct {
	VolumeSnapshot string `json:"volumeSnapshot"`
	StorageClass   string `json:"storageClass"`
	SnapshotClass  string `json:"snapshotClass"`
	Driver         string `json:"driver"`
}

type Progress struct {
	TotalBytes int64 `json:"totalBytes"`
	BytesDone  int64 `json:"bytesDone"`
}

type DataUploadResult struct {
	BackupStorageLocation string            `json:"backupStorageLocation"`
	DataMover             string            `json:"datamover"`
	SnapshotID            string            `json:"snapshotID"`
	SourceNamespace       string            `json:"sourceNamespace"`
	DataMoverResult       map[string]string `json:"dataMoverResult"`
	NodeOS                string            `json:"nodeOS"`
	SnapshotSize          int64             `json:"snapshotSize"`
}

type ConfigMap struct {
	Identity Identity
	Data     map[string]string `json:"data"`
}

type DataDownload struct {
	Identity Identity
	Spec     DataDownloadSpec
	Status   DataDownloadStatus
}

type TargetVolume struct {
	PVC       string `json:"pvc"`
	PV        string `json:"pv"`
	Namespace string `json:"namespace"`
}

// KubernetesReader provides exact GVR reads. Implementations must not fall
// back to discovery-selected versions.
type KubernetesReader interface {
	Get(context.Context, restoreproof.GVR, string, string) ([]byte, error)
	ListPage(context.Context, restoreproof.GVR, string, string, string, int) ([]byte, error)
	ConfirmAbsent(context.Context, restoreproof.GVR, string, string) (bool, error)
}

// KubernetesWatchReader adds an exact resourceVersion-bound watch for the
// short-lived resources whose lifecycle cannot be proven by terminal polling.
type KubernetesWatchReader interface {
	KubernetesReader
	WatchPage(context.Context, restoreproof.GVR, string, string, string, int) ([]WatchEvent, string, error)
}

type WatchEvent struct {
	Type   string
	Object []byte
}

type BaselineRequest struct {
	SchemaVersion   string `json:"schemaVersion"`
	SourceNamespace string `json:"sourceNamespace"`
	SourcePVC       string `json:"sourcePvc"`
	EvidencePrefix  string `json:"evidencePrefix"`
}

type CollectionRequest struct {
	SchemaVersion                string                       `json:"schemaVersion"`
	VeleroNamespace              string                       `json:"veleroNamespace"`
	RestoreName                  string                       `json:"restoreName"`
	SourceNamespace              string                       `json:"sourceNamespace"`
	SourcePVC                    string                       `json:"sourcePvc"`
	TargetNamespace              string                       `json:"targetNamespace"`
	TargetPVC                    string                       `json:"targetPvc"`
	DataUploadName               string                       `json:"dataUploadName"`
	ServerStatusRequestName      string                       `json:"serverStatusRequestName"`
	ServerStatusRequestUIDSHA256 string                       `json:"serverStatusRequestUidSha256"`
	CleanupRunNonceSHA256        string                       `json:"cleanupRunNonceSha256,omitempty"`
	EvidencePrefix               string                       `json:"evidencePrefix"`
	CleanupTimeout               time.Duration                `json:"-"`
	PollInterval                 time.Duration                `json:"-"`
	DataUploadResultObservation  *DataUploadResultObservation `json:"-"`
}

// DataUploadResultObservationRequest identifies the short-lived ConfigMap
// Velero creates and consumes while a restore is running. Observation must be
// started before the Restore is created because Velero deletes this object
// before publishing the terminal Restore status.
type DataUploadResultObservationRequest struct {
	SchemaVersion   string `json:"schemaVersion"`
	VeleroNamespace string `json:"veleroNamespace"`
	RestoreName     string `json:"restoreName"`
	SourceNamespace string `json:"sourceNamespace"`
	SourcePVC       string `json:"sourcePvc"`
	DataUploadName  string `json:"dataUploadName"`
	EvidencePrefix  string `json:"evidencePrefix"`
}

// DataUploadResultObservation is a private, exact copy of the ephemeral live
// ConfigMap plus its observation time. Raw UIDs and payload remain outside the
// source-safe receipt; the collector converts them to digests.
type DataUploadResultObservation struct {
	SchemaVersion  string          `json:"schemaVersion"`
	WatchStartedAt string          `json:"watchStartedAt"`
	ObservedAt     string          `json:"observedAt"`
	CapturedAt     string          `json:"capturedAt"`
	RequestSHA256  string          `json:"requestSha256"`
	EventType      string          `json:"eventType"`
	Object         json.RawMessage `json:"object"`
	ObjectSHA256   string          `json:"objectSha256"`
	EvidenceRef    string          `json:"evidenceRef"`
	EvidenceSHA256 string          `json:"evidenceSha256"`
}

type DataUploadResultObservationReady struct {
	SchemaVersion  string `json:"schemaVersion"`
	Status         string `json:"status"`
	WatchStartedAt string `json:"watchStartedAt"`
	RequestSHA256  string `json:"requestSha256"`
}

type DataUploadResultObservationReadyBarrier interface {
	ReadyForRestore(context.Context, DataUploadResultObservationReady) error
}

type ProbeRequest struct {
	SchemaVersion                 string      `json:"schemaVersion"`
	RequestDigestCanonicalization string      `json:"requestDigestCanonicalization"`
	Challenge                     string      `json:"challenge"`
	AdapterExecutableSHA256       string      `json:"adapterExecutableSha256"`
	Source                        ObjectQuery `json:"source"`
	Target                        ObjectQuery `json:"target"`
}

type ObjectQuery struct {
	GVR       restoreproof.GVR `json:"gvr"`
	Namespace string           `json:"namespace"`
	Name      string           `json:"name"`
	UIDSHA256 string           `json:"uidSha256"`
}

type ProbeObservation struct {
	SchemaVersion           string `json:"schemaVersion"`
	Implementation          string `json:"implementation"`
	Version                 string `json:"version"`
	RequestSHA256           string `json:"requestSha256"`
	AdapterExecutableSHA256 string `json:"adapterExecutableSha256"`
	HashAlgorithm           string `json:"hashAlgorithm"`
	SourceSHA256            string `json:"sourceSha256"`
	TargetSHA256            string `json:"targetSha256"`
	ValidatedBytes          int64  `json:"validatedBytes"`
	StartedAt               string `json:"startedAt"`
	CompletedAt             string `json:"completedAt"`
	EvidenceRef             string `json:"evidenceRef"`
	EvidenceSHA256          string `json:"evidenceSha256"`
}

type ProbeObserver interface {
	IdentitySHA256() string
	Observe(context.Context, ProbeRequest) (ProbeObservation, error)
}

type BackendRequest struct {
	SchemaVersion                 string `json:"schemaVersion"`
	RequestDigestCanonicalization string `json:"requestDigestCanonicalization"`
	Challenge                     string `json:"challenge"`
	AdapterExecutableSHA256       string `json:"adapterExecutableSha256"`
	Operation                     string `json:"operation"`
	SourceKind                    string `json:"sourceKind"`
	ArtifactHandle                string `json:"artifactHandle"`
	ArtifactHandleSHA256          string `json:"artifactHandleSha256"`
}

type BackendObservation struct {
	SchemaVersion           string `json:"schemaVersion"`
	Implementation          string `json:"implementation"`
	Version                 string `json:"version"`
	RequestSHA256           string `json:"requestSha256"`
	AdapterExecutableSHA256 string `json:"adapterExecutableSha256"`
	ArtifactHandleSHA256    string `json:"artifactHandleSha256"`
	Present                 *bool  `json:"present"`
	ObservedAt              string `json:"observedAt"`
	EvidenceRef             string `json:"evidenceRef"`
	EvidenceSHA256          string `json:"evidenceSha256"`
}

type BackendObserver interface {
	IdentitySHA256() string
	Observe(context.Context, BackendRequest) (BackendObservation, error)
}

// CleanupReady is a source-safe synchronization notice. It contains no
// Kubernetes identity, provider handle, or tenant data.
type CleanupReady struct {
	SchemaVersion         string `json:"schemaVersion"`
	Status                string `json:"status"`
	ReadyAt               string `json:"readyAt"`
	CleanupRunNonceSHA256 string `json:"cleanupRunNonceSha256"`
}

// CleanupBarrier publishes the point after which the downstream workflow may
// remove isolated restore resources. A failure must leave cleanup unstarted.
type CleanupBarrier interface {
	ReadyForCleanup(context.Context, CleanupReady) error
}

// PostCleanupObserver is an optional cleanup-barrier capability invoked only
// after the collector has proven all cleanup targets absent and source
// continuity, but before it seals the receipt verification timestamp.
//
// Implementations can use this narrow window to capture exact source-list and
// namespace-absence observations that must be ordered after cleanup and before
// final receipt verification. Returning an error fails the entire collection.
type PostCleanupObserver interface {
	ObservePostCleanup(context.Context) error
}

type Clock interface {
	Now() time.Time
	Wait(context.Context, time.Duration) error
}
