// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package kubeadm

import (
	"fmt"
	"strings"

	"github.com/opencloudtech/CloudRING/pkg/resilience/oneserverloss"
)

// VerifyUpstreamStand independently evaluates sanitized observed state against
// the upstream Kubernetes HA contract.
func VerifyUpstreamStand(inventory StandInventory, receipts ...*oneserverloss.Receipt) (StandReport, error) {
	observed := inventory
	observed.SurviveUnavailableServers = 0
	report := StandReport{
		Status:               "ready",
		WorkflowContinuity:   inventory.WorkflowContinuity,
		DataDurability:       inventory.DataDurability,
		SinglePointOfFailure: inventory.SinglePointOfFailure,
		Observed:             observed,
	}
	add := func(id, category, message string) {
		report.Blockers = append(report.Blockers, Blocker{ID: id, Category: category, Message: message})
	}

	if !strings.EqualFold(strings.TrimSpace(inventory.Distribution), "upstream") {
		add("non_upstream_distribution", "runtime_policy", "cluster distribution must be upstream Kubernetes")
	}
	if !strings.EqualFold(strings.TrimSpace(inventory.Bootstrap), "kubeadm") {
		add("non_kubeadm_bootstrap", "runtime_policy", "cluster bootstrap must be kubeadm")
	}
	serverVersion := strings.ToLower(strings.TrimSpace(inventory.ServerVersion))
	switch {
	case serverVersion == "":
		add("missing_server_version", "runtime_policy", "captured inventory must include Kubernetes server version")
	case strings.Contains(serverVersion, "+k3s"):
		add("legacy_k3s_version", "runtime_policy", "server version contains +k3s and cannot satisfy upstream readiness")
	}
	controlPlaneEndpoint := normalizeEndpoint(inventory.ControlPlaneEndpoint)
	controlPlaneHost := endpointHost(controlPlaneEndpoint)
	if controlPlaneHost == "" {
		add("missing_control_plane_endpoint", "ha_topology", "captured inventory must include the kubeadm controlPlaneEndpoint")
	}
	stableIPv4 := strings.TrimSpace(inventory.StableAPIIPv4)
	stableIPv6 := strings.TrimSpace(inventory.StableAPIIPv6)
	parsedStableIPv4, stableIPv4OK := canonicalAddress(stableIPv4)
	parsedStableIPv6, stableIPv6OK := canonicalAddress(stableIPv6)
	if stableIPv4OK {
		stableIPv4 = parsedStableIPv4.String()
	}
	if stableIPv6OK {
		stableIPv6 = parsedStableIPv6.String()
	}
	if !stableIPv4OK || !parsedStableIPv4.Is4() || !stableIPv6OK || !parsedStableIPv6.Is6() {
		add("stable_api_addresses_missing", "ha_topology", "captured inventory must include stable API IPv4 and IPv6 addresses")
	}
	sans, validSANs := uniqueNormalizedHosts(inventory.APIServingCertificateSANs)
	if !validSANs ||
		!hasDualStackSANs(sans) ||
		!containsString(sans, controlPlaneHost) ||
		!containsString(sans, stableIPv4) ||
		!containsString(sans, stableIPv6) {
		add("api_serving_certificate_sans_missing", "networking", "API serving certificate evidence must cover the endpoint host and the declared stable API IPv4 and IPv6 addresses")
	}
	if inventory.ControlPlaneReplicas < 3 {
		add("missing_control_plane_replicas", "ha_topology", "at least three control-plane replicas are required")
	} else if inventory.ControlPlaneReplicas%2 == 0 {
		add("even_control_plane_replicas", "ha_topology", "stacked-etcd control-plane replica count must be odd")
	}
	if !strings.EqualFold(strings.TrimSpace(inventory.EtcdTopology), "stacked") {
		add("missing_stacked_etcd", "ha_topology", "stacked etcd topology is required for this profile")
	}
	if !HasIPv4AndIPv6CIDRs(inventory.PodCIDRs) {
		add("missing_dual_stack_pod_cidrs", "dual_stack", "pod CIDR inventory must include IPv4 and IPv6 ranges")
	}
	if !HasIPv4AndIPv6CIDRs(inventory.ServiceCIDRs) {
		add("missing_dual_stack_service_cidrs", "dual_stack", "service CIDR inventory must include IPv4 and IPv6 ranges")
	}
	if !inventory.CiliumDualStackReady {
		add("cilium_dual_stack_unready", "networking", "Cilium dual-stack readiness evidence is required")
	}
	if normalizeEndpoint(inventory.CiliumAPIEndpoint) != controlPlaneEndpoint {
		add("cilium_api_endpoint_mismatch", "networking", "Cilium must use the same stable endpoint as kubeadm")
	}
	devices, validDevices := uniqueTrimmed(inventory.CiliumDevices)
	transportDevice := strings.TrimSpace(inventory.ControlPlaneTransportDevice)
	if transportDevice == "" || !validDevices || !containsString(devices, transportDevice) {
		add("cilium_control_plane_device_missing", "networking", "Cilium devices must contain the control-plane transport device")
	}
	if strings.TrimSpace(inventory.ServingCertificateRolloutStrategy) != "one-node-at-a-time" {
		add("serving_certificate_rollout_unsafe", "workflow_continuity", "API serving certificates must be reconfigured one node at a time")
	}
	if !inventory.ServingCertificateReconfigurationReady {
		add("serving_certificate_reconfiguration_unverified", "workflow_continuity", "API serving-certificate reconfiguration evidence is required")
	}
	if !inventory.ServingCertificateRollbackReady {
		add("serving_certificate_rollback_unverified", "workflow_continuity", "API serving-certificate rollback evidence is required")
	}
	if !inventory.ControlPlaneAPIFailoverReady {
		add("control_plane_api_failover_unverified", "single_point_of_failure", "authenticated dual-stack API failover evidence is required")
	}
	if inventory.CoreDNSMinReplicas < 2 || !inventory.CoreDNSSpreadReady {
		add("coredns_spread_missing", "workflow_continuity", "CoreDNS replica and topology-spread evidence is required")
	}
	if !inventory.PodDisruptionBudgetsReady {
		add("missing_pdb_evidence", "workflow_continuity", "PodDisruptionBudget evidence is required")
	}
	if len(inventory.Nodes) != inventory.ControlPlaneReplicas {
		add("node_inventory_replica_mismatch", "ha_topology", "node inventory count must equal the declared control-plane replicas")
	}
	nodeNamesSeen := make(map[string]struct{}, len(inventory.Nodes))
	nodeUIDsSeen := make(map[string]struct{}, len(inventory.Nodes))
	nodeIPv4Seen := make(map[string]struct{}, len(inventory.Nodes))
	nodeIPv6Seen := make(map[string]struct{}, len(inventory.Nodes))
	controlPlaneNodes := 0
	etcdMembers := 0
	for index, node := range inventory.Nodes {
		nodeName := strings.TrimSpace(node.Name)
		blockerSuffix := nodeName
		if !validDNS1123Subdomain(nodeName) {
			blockerSuffix = fmt.Sprintf("entry_%d", index+1)
			add("invalid_node_name_"+blockerSuffix, "ha_topology", "each node inventory entry must use a DNS-1123 name")
		}
		parsedNodeIPv4, nodeIPv4OK := canonicalAddress(node.NodeIPv4)
		parsedNodeIPv6, nodeIPv6OK := canonicalAddress(node.NodeIPv6)
		nodeIPv4 := ""
		nodeIPv6 := ""
		if nodeIPv4OK && parsedNodeIPv4.Is4() {
			nodeIPv4 = parsedNodeIPv4.String()
		}
		if nodeIPv6OK && parsedNodeIPv6.Is6() {
			nodeIPv6 = parsedNodeIPv6.String()
		}
		if _, exists := nodeNamesSeen[nodeName]; exists {
			add("duplicate_node_name", "ha_topology", "control-plane node names must be unique")
		}
		if !sha256Pattern.MatchString(node.UIDSHA256) {
			add("node_uid_binding_invalid_"+blockerSuffix, "ha_topology", "each node inventory entry must include a SHA-256 UID binding")
		} else if _, exists := nodeUIDsSeen[node.UIDSHA256]; exists {
			add("duplicate_node_uid_binding", "ha_topology", "control-plane node UID bindings must be unique")
		}
		if nodeIPv4 != "" {
			if _, exists := nodeIPv4Seen[nodeIPv4]; exists {
				add("duplicate_node_ipv4", "ha_topology", "control-plane IPv4 addresses must be unique")
			}
			nodeIPv4Seen[nodeIPv4] = struct{}{}
		}
		if nodeIPv6 != "" {
			if _, exists := nodeIPv6Seen[nodeIPv6]; exists {
				add("duplicate_node_ipv6", "ha_topology", "control-plane IPv6 addresses must be unique")
			}
			nodeIPv6Seen[nodeIPv6] = struct{}{}
		}
		nodeNamesSeen[nodeName] = struct{}{}
		if sha256Pattern.MatchString(node.UIDSHA256) {
			nodeUIDsSeen[node.UIDSHA256] = struct{}{}
		}
		if !node.Ready {
			add("node_not_ready_"+blockerSuffix, "workflow_continuity", "node must be Ready")
		}
		if !node.ControlPlane {
			add("node_missing_control_plane_"+blockerSuffix, "ha_topology", "node must carry the control-plane role")
		} else {
			controlPlaneNodes++
		}
		if !node.EtcdMember {
			add("node_missing_etcd_"+blockerSuffix, "data_durability", "node must be an etcd member in stacked topology")
		} else {
			etcdMembers++
		}
		if nodeIPv4 == "" || nodeIPv6 == "" {
			add("node_missing_dual_stack_ip_"+blockerSuffix, "dual_stack", "node inventory must include IPv4 and IPv6 node-ip evidence")
		}
		if controlPlaneHost == nodeIPv4 || controlPlaneHost == nodeIPv6 {
			add("node_bound_control_plane_endpoint", "ha_topology", "control plane endpoint must not be any node address")
		}
		if stableIPv4 == nodeIPv4 || stableIPv6 == nodeIPv6 {
			add("node_bound_stable_api_address", "ha_topology", "stable API addresses must not be any node address")
		}
	}
	if validOneServerLossReceiptBinding(inventory, receipts, nodeUIDsSeen, controlPlaneNodes, etcdMembers) {
		report.VerifiedSurviveUnavailableServers = 1
	} else {
		add("missing_one_server_loss_evidence", "ha_topology", "readiness requires a valid identity-bound one-server-loss receipt")
	}
	requireEvidence := func(id, category string, evidence EvidenceInventory) {
		if strings.TrimSpace(evidence.Summary) == "" || len(trimmedCopy(evidence.Items)) == 0 {
			add(id, category, "required readiness evidence inventory is missing")
		}
	}
	requireEvidence("missing_workflow_continuity_evidence", "workflow_continuity", inventory.WorkflowContinuity)
	requireEvidence("missing_data_durability_evidence", "data_durability", inventory.DataDurability)
	requireEvidence("missing_spof_inventory", "single_point_of_failure", inventory.SinglePointOfFailure)

	if len(report.Blockers) > 0 {
		report.Status = "blocked"
		return report, fmt.Errorf("verify upstream stand: %w", ErrStandBlocked)
	}
	return report, nil
}

func validOneServerLossReceiptBinding(
	inventory StandInventory,
	receipts []*oneserverloss.Receipt,
	nodeUIDs map[string]struct{},
	controlPlaneNodes, etcdMembers int,
) bool {
	if len(receipts) != 1 || receipts[0] == nil {
		return false
	}
	receipt := receipts[0]
	if err := oneserverloss.ValidateReceipt(receipt); err != nil {
		return false
	}
	binding := inventory.OneServerLossReceipt
	if !sha256Pattern.MatchString(binding.ReceiptSHA256) ||
		!sha256Pattern.MatchString(binding.RunNonceSHA256) ||
		!sha256Pattern.MatchString(binding.TargetNodeUIDSHA256) ||
		!sha256Pattern.MatchString(binding.KubectlExecutableSHA256) ||
		!sha256Pattern.MatchString(binding.ProbeAdapterSHA256) ||
		binding.ReceiptSHA256 != receipt.ReceiptSHA256 ||
		binding.RunNonceSHA256 != receipt.RunNonceSHA256 ||
		binding.TargetNodeUIDSHA256 != receipt.TargetNodeUIDSHA256 ||
		binding.KubectlExecutableSHA256 != receipt.KubectlExecutableSHA256 ||
		binding.ProbeAdapterSHA256 != receipt.ProbeAdapterSHA256 {
		return false
	}
	if _, targetPresent := nodeUIDs[receipt.TargetNodeUIDSHA256]; !targetPresent {
		return false
	}
	if receipt.Baseline.ControlPlaneMemberSetSHA256 != "" &&
		(binding.NodeUIDHashAlgorithm != receipt.NodeUIDHashAlgorithm ||
			binding.ControlPlaneMemberSetSHA256 != receipt.Baseline.ControlPlaneMemberSetSHA256 ||
			oneserverloss.ControlPlaneMemberSetSHA256(mapHAWaveMemberUIDs(nodeUIDs)) != receipt.Baseline.ControlPlaneMemberSetSHA256) {
		return false
	}
	return receipt.Baseline.ControlPlaneNodes == controlPlaneNodes &&
		receipt.Baseline.ControlPlaneNodes == inventory.ControlPlaneReplicas &&
		receipt.Baseline.EtcdMembers == etcdMembers &&
		receipt.Baseline.APIServerMembers == controlPlaneNodes &&
		receipt.MinimumControlPlane <= controlPlaneNodes
}
