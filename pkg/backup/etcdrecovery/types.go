// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

// Package etcdrecovery implements a provider-neutral, offline etcd snapshot
// recovery worker. It never connects to a live etcd endpoint. Its only network
// surface is a bounded, exact-version HTTPS fetch from an S3-compatible object
// store before all snapshot inspection and restore work proceeds offline.
package etcdrecovery

import "time"

const (
	RequestSchemaVersion         = "cloudring.etcd-recovery.request/v1"
	ReceiptSchemaVersion         = "cloudring.etcd-recovery.receipt/v1"
	InputProjectionSchemaVersion = "cloudring.etcd-recovery.input-secret-projection/v1"
	ImageIdentitySchemaVersion   = "cloudring.etcd-recovery.image-identity/v1"
	SandboxStateSchemaVersion    = "cloudring.etcd-recovery.sandbox-state/v1"
	ToolName                     = "etcdutl"
	ToolVersion                  = "3.6.13"
	ToolSHA256                   = "d3b1ab51f3277a60ee37dfd749941e663c14184d5bc0c26d0cf06f5414d18199"

	DefaultRequestPath     = "/run/cloudring/request/request.json"
	DefaultArchivePath     = "/run/cloudring/archive/snapshot.db"
	DefaultAuthMountRoot   = "/run/cloudring/credentials"
	SharedCredentialsKey   = "cloud"
	DefaultToolPath        = "/usr/local/bin/etcdutl"
	DefaultWorkspace       = "/work"
	DefaultReceiptPath     = "/work/output/receipt.json"
	MaxRequestBytes        = 64 << 10
	MaxArchiveBytes        = 2 << 30
	MaxRestoredBytes       = 2 << 30
	MaxRestoredFiles       = 1024
	MaximumRunTimeout      = 30 * time.Minute
	MaximumCleanupTimeout  = 30 * time.Second
	MaximumReceiptDuration = MaximumRunTimeout + MaximumCleanupTimeout
	MaximumRequestAge      = 30 * time.Minute
	MaximumFutureSkew      = 5 * time.Minute
	maximumToolBytes       = 256 << 20
	maximumToolOutput      = 64 << 10
	maximumCredentialBytes = 8 << 10
	maximumReceiptBytes    = 4 << 10
)

// Request is the complete canonical input. Raw object identity fields are
// consumed only to recompute ObjectIdentitySHA256 and are never emitted.
type Request struct {
	SchemaVersion          string `json:"schemaVersion"`
	OperationID            string `json:"operationId"`
	SnapshotID             string `json:"snapshotId"`
	SnapshotChecksumSHA256 string `json:"snapshotChecksumSha256"`
	SnapshotBytes          int64  `json:"snapshotBytes"`
	SourceMode             string `json:"sourceMode"`
	Endpoint               string `json:"endpoint"`
	Region                 string `json:"region"`
	Bucket                 string `json:"bucket"`
	ObjectKey              string `json:"objectKey"`
	ObjectVersion          string `json:"objectVersion"`
	ObjectIdentitySHA256   string `json:"objectIdentitySha256"`
	ClusterIdentitySHA256  string `json:"clusterIdentitySha256"`
	JobTemplateSHA256      string `json:"jobTemplateSha256"`
	ExecutionProfileSHA256 string `json:"executionProfileSha256"`
	InputSecretSHA256      string `json:"inputSecretSha256"`
	WorkerExecutableSHA256 string `json:"workerExecutableSha256"`
	WorkerImageDigest      string `json:"workerImageDigest"`
	EtcdutlVersion         string `json:"etcdutlVersion"`
	EtcdutlSHA256          string `json:"etcdutlSha256"`
	IssuedAt               string `json:"issuedAt"`
	ExpiresAt              string `json:"expiresAt"`
	TimeoutSeconds         int    `json:"timeoutSeconds"`
}

// S3ObjectVersionLookup is the minimum protected input needed to resolve the
// exact immutable version of an already uploaded recovery object. Callers keep
// the returned raw version in a protected runtime boundary and publish only its
// SHA-256 binding.
type S3ObjectVersionLookup struct {
	Endpoint            string `json:"endpoint"`
	Region              string `json:"region"`
	Bucket              string `json:"bucket"`
	ObjectKey           string `json:"objectKey"`
	ObjectVersionSHA256 string `json:"objectVersionSha256"`
	ExpectedBytes       int64  `json:"expectedBytes"`
}

type ToolIdentity struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	ExecutableSHA256 string `json:"executableSha256"`
}

// InputSecretProjection is the non-self-referential contract hashed into
// Request.InputSecretSHA256. It identifies the reviewed Secret projection
// configuration, not request.json bytes and not a Secret data digest.
// Downstream evidence must bind the actual Secret UID/resourceVersion and Pod
// volume to this reviewed contract separately.
type InputSecretProjection struct {
	SchemaVersion       string `json:"schemaVersion"`
	Namespace           string `json:"namespace"`
	ProjectedObjectName string `json:"secretName"`
	SecretKey           string `json:"secretKey"`
	MountPath           string `json:"mountPath"`
	DefaultMode         int    `json:"defaultMode"`
	Optional            bool   `json:"optional"`
	ReadOnly            bool   `json:"readOnly"`
}

// Receipt is deliberately source-safe: it contains hashes, sizes, fixed tool
// identity, and timestamps, but no endpoint, object key/version, archive path,
// credential, snapshot ID, or recovered tenant data.
type Receipt struct {
	SchemaVersion                 string        `json:"schemaVersion"`
	Status                        string        `json:"status"`
	ReasonCode                    string        `json:"reasonCode"`
	Stage                         string        `json:"stage"`
	SnapshotIDSHA256              string        `json:"snapshotIdSha256,omitempty"`
	SnapshotChecksumSHA256        string        `json:"snapshotChecksumSha256,omitempty"`
	SnapshotBytes                 int64         `json:"snapshotBytes,omitempty"`
	SourceMode                    string        `json:"sourceMode,omitempty"`
	EndpointSHA256                string        `json:"endpointSha256,omitempty"`
	ObjectReferenceSHA256         string        `json:"objectReferenceSha256,omitempty"`
	ObjectIdentitySHA256          string        `json:"objectIdentitySha256,omitempty"`
	ClusterIdentitySHA256         string        `json:"clusterIdentitySha256,omitempty"`
	JobTemplateSHA256             string        `json:"jobTemplateSha256,omitempty"`
	ExecutionProfileSHA256        string        `json:"executionProfileSha256,omitempty"`
	InputSecretSHA256             string        `json:"inputSecretSha256,omitempty"`
	RequestSHA256                 string        `json:"requestSha256,omitempty"`
	WorkerExecutableSHA256        string        `json:"workerExecutableSha256,omitempty"`
	WorkerImageDigest             string        `json:"workerImageDigest,omitempty"`
	Tool                          *ToolIdentity `json:"tool,omitempty"`
	SourceStatusSHA256            string        `json:"sourceStatusSha256,omitempty"`
	SourceKVHashSHA256            string        `json:"sourceKvHashSha256,omitempty"`
	RestoredChecksumSHA256        string        `json:"restoredChecksumSha256,omitempty"`
	RestoredBytes                 int64         `json:"restoredBytes,omitempty"`
	RestoredStatusSHA256          string        `json:"restoredStatusSha256,omitempty"`
	RestoredKVHashSHA256          string        `json:"restoredKvHashSha256,omitempty"`
	SandboxStateSHA256            string        `json:"sandboxStateSha256,omitempty"`
	MemberHealthVerified          bool          `json:"memberHealthVerified"`
	OfflineMemberDatabaseVerified bool          `json:"offlineMemberDatabaseVerified"`
	LoopbackOnly                  bool          `json:"loopbackOnly"`
	WorkspaceCleanupVerified      bool          `json:"workspaceCleanupVerified"`
	StartedAt                     string        `json:"startedAt"`
	CompletedAt                   string        `json:"completedAt"`
	ObservedDurationMilliseconds  int64         `json:"observedDurationMilliseconds"`
	EvidenceSHA256                string        `json:"evidenceSha256"`
}

type snapshotStatus struct {
	Hash      uint32 `json:"hash"`
	Revision  int64  `json:"revision"`
	TotalKey  int64  `json:"totalKey"`
	TotalSize int64  `json:"totalSize"`
	Version   string `json:"version"`
}

type snapshotKVHash struct {
	Hash            uint32 `json:"hash"`
	HashRevision    int64  `json:"hashRevision"`
	CompactRevision int64  `json:"compactRevision"`
}

type objectIdentity struct {
	SchemaVersion string `json:"schemaVersion"`
	SnapshotID    string `json:"snapshotId"`
	SourceMode    string `json:"sourceMode"`
	Endpoint      string `json:"endpoint"`
	Region        string `json:"region"`
	Bucket        string `json:"bucket"`
	ObjectKey     string `json:"objectKey"`
	ObjectVersion string `json:"objectVersion"`
}

type sandboxState struct {
	SchemaVersion          string `json:"schemaVersion"`
	SourceStatusSHA256     string `json:"sourceStatusSha256"`
	SourceKVHashSHA256     string `json:"sourceKvHashSha256"`
	RestoredStatusSHA256   string `json:"restoredStatusSha256"`
	RestoredKVHashSHA256   string `json:"restoredKvHashSha256"`
	RestoredChecksumSHA256 string `json:"restoredChecksumSha256"`
	RestoredBytes          int64  `json:"restoredBytes"`
	LoopbackPeerURL        string `json:"loopbackPeerUrl"`
}
