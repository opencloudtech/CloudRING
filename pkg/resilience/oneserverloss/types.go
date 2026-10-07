// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

// Package oneserverloss collects and verifies provider-neutral evidence that a
// CloudRING installation survives the loss and recovery of one server. The
// observer never causes the fault; an installation-owned, separately approved
// procedure does that only after the ready marker is published.
package oneserverloss

import (
	"context"
	"errors"
	"time"
)

const (
	RequestSchemaVersion       = "cloudring.one-server-loss.observation-request/v1"
	ReadyMarkerSchemaVersion   = "cloudring.one-server-loss.ready-marker/v1"
	ReceiptSchemaVersion       = "cloudring.one-server-loss.receipt/v1"
	ProbeRequestSchemaVersion  = "cloudring.one-server-loss.data-probe-request/v1"
	ProbeResponseSchemaVersion = "cloudring.one-server-loss.data-probe-response/v1"

	ReadyMarkerStatus = "ready-for-fault"
	ReceiptStatus     = "completed"

	PhasePreLoss   = "pre-loss"
	PhaseLoss      = "loss"
	PhaseRecovered = "recovered"

	controlPlaneMemberSetDomain = "cloudring.one-server-loss.control-plane-member-set/v1"
)

// Request is private installation input. Names, namespaces, label bindings,
// and query references are deliberately never copied into the receipt.
type Request struct {
	SchemaVersion              string           `json:"schemaVersion"`
	RunNonceSHA256             string           `json:"runNonceSha256"`
	TargetNodeName             string           `json:"targetNodeName"`
	PollInterval               string           `json:"pollInterval"`
	FaultArrivalTimeout        string           `json:"faultArrivalTimeout"`
	MinimumLossWindow          string           `json:"minimumLossWindow"`
	RecoveryTimeout            string           `json:"recoveryTimeout"`
	RecoveryStabilityWindow    string           `json:"recoveryStabilityWindow"`
	MinimumControlPlaneMembers int              `json:"minimumControlPlaneMembers"`
	Workloads                  []WorkloadTarget `json:"workloads"`
	VM                         VMTarget         `json:"vm"`
	DataProbe                  DataProbeTarget  `json:"dataProbe"`
}

type WorkloadTarget struct {
	ID                        string            `json:"id"`
	Namespace                 string            `json:"namespace"`
	MatchLabels               map[string]string `json:"matchLabels"`
	MinimumReadyPods          int               `json:"minimumReadyPods"`
	MinimumDistinctReadyNodes int               `json:"minimumDistinctReadyNodes"`
}

type VMTarget struct {
	ID                         string `json:"id"`
	Namespace                  string `json:"namespace"`
	Name                       string `json:"name"`
	RequirePreLossOnTarget     bool   `json:"requirePreLossOnTarget"`
	MaximumUnavailableDuration string `json:"maximumUnavailableDuration"`
}

type DataProbeTarget struct {
	ID                    string `json:"id"`
	QueryRef              string `json:"queryRef"`
	MinimumValidatedBytes int64  `json:"minimumValidatedBytes"`
}

// ReadyMarker is a private, atomic hand-off to the installation-owned fault
// procedure. It contains hashes and counts, never private Kubernetes names.
type ReadyMarker struct {
	SchemaVersion               string `json:"schemaVersion"`
	Status                      string `json:"status"`
	RequestSHA256               string `json:"requestSha256"`
	RunNonceSHA256              string `json:"runNonceSha256"`
	TargetNodeUIDSHA256         string `json:"targetNodeUidSha256"`
	NodeUIDHashAlgorithm        string `json:"nodeUidHashAlgorithm,omitempty"`
	KubectlExecutableSHA256     string `json:"kubectlExecutableSha256"`
	ProbeAdapterSHA256          string `json:"probeAdapterSha256"`
	ControlPlaneMemberSetSHA256 string `json:"controlPlaneMemberSetSha256,omitempty"`
	BaselineControlPlaneNodes   int    `json:"baselineControlPlaneNodes"`
	BaselineEtcdMembers         int    `json:"baselineEtcdMembers"`
	BaselineAPIServerMembers    int    `json:"baselineApiServerMembers"`
	ReadyAt                     string `json:"readyAt"`
	MarkerSHA256                string `json:"markerSha256"`
}

type Receipt struct {
	SchemaVersion           string        `json:"schemaVersion"`
	Status                  string        `json:"status"`
	RequestSHA256           string        `json:"requestSha256"`
	RunNonceSHA256          string        `json:"runNonceSha256"`
	TargetNodeUIDSHA256     string        `json:"targetNodeUidSha256"`
	NodeUIDHashAlgorithm    string        `json:"nodeUidHashAlgorithm,omitempty"`
	KubectlExecutableSHA256 string        `json:"kubectlExecutableSha256"`
	ProbeAdapterSHA256      string        `json:"probeAdapterSha256"`
	StartedAt               string        `json:"startedAt"`
	ReadyMarkerAt           string        `json:"readyMarkerAt"`
	CompletedAt             string        `json:"completedAt"`
	PollInterval            string        `json:"pollInterval"`
	FaultArrivalTimeout     string        `json:"faultArrivalTimeout"`
	MinimumLossWindow       string        `json:"minimumLossWindow"`
	RecoveryTimeout         string        `json:"recoveryTimeout"`
	RecoveryStabilityWindow string        `json:"recoveryStabilityWindow"`
	MaximumVMUnavailable    string        `json:"maximumVmUnavailable"`
	MinimumControlPlane     int           `json:"minimumControlPlane"`
	Baseline                Baseline      `json:"baseline"`
	PreLoss                 PhaseEvidence `json:"preLoss"`
	Loss                    PhaseEvidence `json:"loss"`
	Recovered               PhaseEvidence `json:"recovered"`
	ReceiptSHA256           string        `json:"receiptSha256"`
}

type Baseline struct {
	ControlPlaneNodes           int    `json:"controlPlaneNodes"`
	EtcdMembers                 int    `json:"etcdMembers"`
	APIServerMembers            int    `json:"apiServerMembers"`
	VMUIDSHA256                 string `json:"vmUidSha256"`
	DataSHA256                  string `json:"dataSha256"`
	ValidatedBytes              int64  `json:"validatedBytes"`
	ControlPlaneMemberSetSHA256 string `json:"controlPlaneMemberSetSha256,omitempty"`
	BaselineSHA256              string `json:"baselineSha256"`
}

type PhaseEvidence struct {
	Phase         string           `json:"phase"`
	StartedAt     string           `json:"startedAt"`
	CompletedAt   string           `json:"completedAt"`
	Samples       []SampleEvidence `json:"samples"`
	SamplesSHA256 string           `json:"samplesSha256"`
}

type SampleEvidence struct {
	Sequence                    int64              `json:"sequence"`
	Phase                       string             `json:"phase"`
	StartedAt                   string             `json:"startedAt"`
	ObservedAt                  string             `json:"observedAt"`
	TargetNodePresent           bool               `json:"targetNodePresent"`
	TargetNodeReady             bool               `json:"targetNodeReady"`
	TargetNodeUIDSHA256         string             `json:"targetNodeUidSha256,omitempty"`
	ReadyZPassed                bool               `json:"readyzPassed"`
	ControlPlaneReadyNodes      int                `json:"controlPlaneReadyNodes"`
	EtcdReadyMembers            int                `json:"etcdReadyMembers"`
	APIServerReadyMembers       int                `json:"apiServerReadyMembers"`
	ControlPlaneMemberSetSHA256 string             `json:"controlPlaneMemberSetSha256,omitempty"`
	TargetHostsEtcd             bool               `json:"targetHostsEtcd"`
	TargetHostsAPIServer        bool               `json:"targetHostsApiServer"`
	Workloads                   []WorkloadEvidence `json:"workloads"`
	VM                          VMEvidence         `json:"vm"`
	DataProbe                   DataProbeEvidence  `json:"dataProbe"`
	SampleSHA256                string             `json:"sampleSha256"`
}

type WorkloadEvidence struct {
	ID                 string `json:"id"`
	BindingSHA256      string `json:"bindingSha256"`
	ReadyPods          int    `json:"readyPods"`
	DistinctReadyNodes int    `json:"distinctReadyNodes"`
	MinimumReadyPods   int    `json:"minimumReadyPods"`
	MinimumReadyNodes  int    `json:"minimumReadyNodes"`
}

type VMEvidence struct {
	ID            string `json:"id"`
	BindingSHA256 string `json:"bindingSha256"`
	VMUIDSHA256   string `json:"vmUidSha256"`
	VMIUIDSHA256  string `json:"vmiUidSha256,omitempty"`
	VMReady       bool   `json:"vmReady"`
	VMIReady      bool   `json:"vmiReady"`
	VMIOnTarget   bool   `json:"vmiOnTarget"`
}

type DataProbeEvidence struct {
	ID                      string `json:"id"`
	BindingSHA256           string `json:"bindingSha256"`
	Implementation          string `json:"implementation"`
	Version                 string `json:"version"`
	RequestSHA256           string `json:"requestSha256"`
	AdapterExecutableSHA256 string `json:"adapterExecutableSha256"`
	HashAlgorithm           string `json:"hashAlgorithm"`
	DataSHA256              string `json:"dataSha256"`
	ValidatedBytes          int64  `json:"validatedBytes"`
	StartedAt               string `json:"startedAt"`
	CompletedAt             string `json:"completedAt"`
}

type ProbeRequest struct {
	SchemaVersion           string `json:"schemaVersion"`
	RunNonceSHA256          string `json:"runNonceSha256"`
	ParentRequestSHA256     string `json:"parentRequestSha256"`
	Phase                   string `json:"phase"`
	Sequence                int64  `json:"sequence"`
	ProbeID                 string `json:"probeId"`
	QueryRef                string `json:"queryRef"`
	AdapterExecutableSHA256 string `json:"adapterExecutableSha256"`
}

type ProbeResponse struct {
	SchemaVersion           string `json:"schemaVersion"`
	Implementation          string `json:"implementation"`
	Version                 string `json:"version"`
	RequestSHA256           string `json:"requestSha256"`
	AdapterExecutableSHA256 string `json:"adapterExecutableSha256"`
	HashAlgorithm           string `json:"hashAlgorithm"`
	DataSHA256              string `json:"dataSha256"`
	ValidatedBytes          int64  `json:"validatedBytes"`
	StartedAt               string `json:"startedAt"`
	CompletedAt             string `json:"completedAt"`
}

type Resource struct {
	Group    string
	Version  string
	Resource string
	ListKind string
	Kind     string
}

var ErrNotFound = errors.New("Kubernetes object not found")

// Reader is a content-pinned, read-only Kubernetes transport.
type Reader interface {
	IdentitySHA256() string
	ListPage(context.Context, Resource, string, string, string, int) ([]byte, error)
	Get(context.Context, Resource, string, string) ([]byte, error)
	ReadyZ(context.Context) error
}

// Probe invokes one content-pinned installation-owned, read-only data query.
type Probe interface {
	IdentitySHA256() string
	Observe(context.Context, ProbeRequest) (ProbeResponse, error)
}

type ReadyBarrier interface {
	ReadyForFault(context.Context, ReadyMarker) error
}

type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}
