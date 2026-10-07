// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package kubeadm

import "errors"

var (
	// ErrInvalidBootstrapSpec marks an invalid or incomplete bootstrap input.
	ErrInvalidBootstrapSpec = errors.New("kubeadm bootstrap spec invalid")
	// ErrStandBlocked marks captured stand state which failed acceptance.
	ErrStandBlocked = errors.New("upstream stand readiness blocked")
)

// BootstrapSpec is the provider-resolved input to the deterministic renderer.
type BootstrapSpec struct {
	ClusterName                 string                      `json:"clusterName"`
	KubernetesVersion           string                      `json:"kubernetesVersion"`
	ControlPlaneEndpoint        string                      `json:"controlPlaneEndpoint"`
	StableAPIIPv4               string                      `json:"stableAPIIPv4"`
	StableAPIIPv6               string                      `json:"stableAPIIPv6"`
	APIServingCertificateSANs   []string                    `json:"apiServingCertificateSANs"`
	ControlPlaneReplicas        int                         `json:"controlPlaneReplicas"`
	EtcdTopology                string                      `json:"etcdTopology"`
	PodCIDRs                    []string                    `json:"podCIDRs"`
	ServiceCIDRs                []string                    `json:"serviceCIDRs"`
	SurviveUnavailableServers   int                         `json:"surviveUnavailableServers"`
	CiliumVersionRef            string                      `json:"ciliumVersionRef"`
	CiliumDualStackMode         string                      `json:"ciliumDualStackMode"`
	CiliumAPIEndpoint           string                      `json:"ciliumAPIEndpoint"`
	ControlPlaneTransportDevice string                      `json:"controlPlaneTransportDevice"`
	CiliumDevices               []string                    `json:"ciliumDevices"`
	ServingCertificateLifecycle ServingCertificateLifecycle `json:"servingCertificateLifecycle"`
	ContainerRuntimeSocket      string                      `json:"containerRuntimeSocket"`
	CoreDNSMinReplicas          int                         `json:"coreDNSMinReplicas"`
	CoreDNSTopologyKey          string                      `json:"coreDNSTopologyKey"`
	RequiredPodDisruptionNames  []string                    `json:"requiredPodDisruptionNames"`
	Nodes                       []NodeSpec                  `json:"nodes"`
}

// ServingCertificateLifecycle binds sequential certificate maintenance to
// rollback and one-server-loss acceptance workflows.
type ServingCertificateLifecycle struct {
	RolloutStrategy            string `json:"rolloutStrategy"`
	ReconfigurationPlanRef     string `json:"reconfigurationPlanRef"`
	RollbackPlanRef            string `json:"rollbackPlanRef"`
	OneServerLossAcceptanceRef string `json:"oneServerLossAcceptanceRef"`
}

// NodeSpec describes one control-plane node without credentials.
type NodeSpec struct {
	Name          string            `json:"name"`
	AdvertiseIPv4 string            `json:"advertiseIPv4"`
	AdvertiseIPv6 string            `json:"advertiseIPv6"`
	Roles         []string          `json:"roles,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Taints        []string          `json:"taints,omitempty"`
}

// BootstrapBundle contains rendered documents and non-executing operation
// metadata.
type BootstrapBundle struct {
	InitYAML                    string                      `json:"initYAML"`
	ControlPlaneJoinYAML        []JoinDocument              `json:"controlPlaneJoinYAML"`
	SurviveUnavailableServers   int                         `json:"surviveUnavailableServers"`
	Actions                     []NodeAction                `json:"actions"`
	Cilium                      CiliumReadiness             `json:"cilium"`
	ServingCertificateLifecycle ServingCertificateLifecycle `json:"servingCertificateLifecycle"`
	CoreDNS                     CoreDNSExpectation          `json:"coreDNS"`
	PodDisruptionBudgets        []string                    `json:"podDisruptionBudgets"`
}

// JoinDocument binds one node name to its source-safe join configuration.
type JoinDocument struct {
	NodeName string `json:"nodeName"`
	YAML     string `json:"yaml"`
}

// NodeAction describes an ordered operation without executing it.
type NodeAction struct {
	Name                   string   `json:"name"`
	Description            string   `json:"description"`
	Operation              string   `json:"operation"`
	Nodes                  []string `json:"nodes"`
	ReadOnlyPlanned        bool     `json:"readOnlyPlanned"`
	Evidence               string   `json:"evidence"`
	ReconfigurationPlanRef string   `json:"reconfigurationPlanRef,omitempty"`
	RollbackPlanRef        string   `json:"rollbackPlanRef,omitempty"`
	AcceptancePlanRef      string   `json:"acceptancePlanRef,omitempty"`
}

// CiliumReadiness captures the required API endpoint, device set, and checks.
type CiliumReadiness struct {
	DualStack                   bool     `json:"dualStack"`
	VersionRef                  string   `json:"versionRef"`
	Mode                        string   `json:"mode"`
	APIEndpoint                 string   `json:"apiEndpoint"`
	ControlPlaneTransportDevice string   `json:"controlPlaneTransportDevice"`
	Devices                     []string `json:"devices"`
	Checks                      []string `json:"checks"`
}

// CoreDNSExpectation describes the minimum replicated DNS topology.
type CoreDNSExpectation struct {
	MinReplicas int    `json:"minReplicas"`
	TopologyKey string `json:"topologyKey"`
}

// StandInventory is sanitized observed state consumed by the independent
// verifier.
type StandInventory struct {
	Distribution              string   `json:"distribution"`
	Bootstrap                 string   `json:"bootstrap"`
	ServerVersion             string   `json:"serverVersion"`
	ControlPlaneEndpoint      string   `json:"controlPlaneEndpoint"`
	StableAPIIPv4             string   `json:"stableAPIIPv4"`
	StableAPIIPv6             string   `json:"stableAPIIPv6"`
	APIServingCertificateSANs []string `json:"apiServingCertificateSANs"`
	ControlPlaneReplicas      int      `json:"controlPlaneReplicas"`
	EtcdTopology              string   `json:"etcdTopology"`
	PodCIDRs                  []string `json:"podCIDRs"`
	ServiceCIDRs              []string `json:"serviceCIDRs"`
	// SurviveUnavailableServers is a deprecated input-only compatibility field.
	// VerifyUpstreamStand ignores it and strips it from Observed; only
	// VerifiedSurviveUnavailableServers carries verified evidence.
	SurviveUnavailableServers              int                         `json:"surviveUnavailableServers,omitempty"`
	OneServerLossReceipt                   OneServerLossReceiptBinding `json:"oneServerLossReceipt"`
	CiliumDualStackReady                   bool                        `json:"ciliumDualStackReady"`
	CiliumAPIEndpoint                      string                      `json:"ciliumAPIEndpoint"`
	ControlPlaneTransportDevice            string                      `json:"controlPlaneTransportDevice"`
	CiliumDevices                          []string                    `json:"ciliumDevices"`
	ServingCertificateRolloutStrategy      string                      `json:"servingCertificateRolloutStrategy"`
	ServingCertificateReconfigurationReady bool                        `json:"servingCertificateReconfigurationReady"`
	ServingCertificateRollbackReady        bool                        `json:"servingCertificateRollbackReady"`
	ControlPlaneAPIFailoverReady           bool                        `json:"controlPlaneAPIFailoverReady"`
	CoreDNSMinReplicas                     int                         `json:"coreDNSMinReplicas"`
	CoreDNSSpreadReady                     bool                        `json:"coreDNSSpreadReady"`
	PodDisruptionBudgetsReady              bool                        `json:"podDisruptionBudgetsReady"`
	Nodes                                  []NodeInventory             `json:"nodes"`
	WorkflowContinuity                     EvidenceInventory           `json:"workflowContinuity"`
	DataDurability                         EvidenceInventory           `json:"dataDurability"`
	SinglePointOfFailure                   EvidenceInventory           `json:"singlePointOfFailure"`
}

// NodeInventory is sanitized observed state for one control-plane node.
type NodeInventory struct {
	Name         string `json:"name"`
	UIDSHA256    string `json:"uidSha256"`
	Ready        bool   `json:"ready"`
	ControlPlane bool   `json:"controlPlane"`
	EtcdMember   bool   `json:"etcdMember"`
	NodeIPv4     string `json:"nodeIPv4"`
	NodeIPv6     string `json:"nodeIPv6"`
}

// OneServerLossReceiptBinding binds the stand inventory to one exact,
// independently validated resilience receipt and, when supplied, its complete
// privacy-safe control-plane member set without embedding the receipt in the
// sanitized stand report.
type OneServerLossReceiptBinding struct {
	ReceiptSHA256               string `json:"receiptSha256"`
	RunNonceSHA256              string `json:"runNonceSha256"`
	TargetNodeUIDSHA256         string `json:"targetNodeUidSha256"`
	KubectlExecutableSHA256     string `json:"kubectlExecutableSha256"`
	ProbeAdapterSHA256          string `json:"probeAdapterSha256"`
	NodeUIDHashAlgorithm        string `json:"nodeUidHashAlgorithm,omitempty"`
	ControlPlaneMemberSetSHA256 string `json:"controlPlaneMemberSetSha256,omitempty"`
}

// EvidenceInventory records source-safe evidence identifiers and a summary.
type EvidenceInventory struct {
	Summary string   `json:"summary"`
	Items   []string `json:"items"`
}

// StandReport is the fail-closed verification result.
type StandReport struct {
	Status                            string            `json:"status"`
	VerifiedSurviveUnavailableServers int               `json:"verifiedSurviveUnavailableServers"`
	Blockers                          []Blocker         `json:"blockers,omitempty"`
	WorkflowContinuity                EvidenceInventory `json:"workflowContinuity"`
	DataDurability                    EvidenceInventory `json:"dataDurability"`
	SinglePointOfFailure              EvidenceInventory `json:"singlePointOfFailure"`
	Observed                          StandInventory    `json:"observed"`
}

// Blocker identifies one failed acceptance condition.
type Blocker struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Message  string `json:"message"`
}
