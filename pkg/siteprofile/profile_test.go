// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package siteprofile

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestSyntheticProfilePassesAndPlanIsDeterministic(t *testing.T) {
	profile := parseFixture(t, validProfileYAML)
	report := Validate(profile)
	if report.Status != "ready" || len(report.Blockers) != 0 || len(report.ProfileDigest) != 64 {
		t.Fatalf("unexpected report: %#v", report)
	}
	first, err := BuildPlan(profile)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildPlan(profile)
	if err != nil {
		t.Fatal(err)
	}
	if first.ProfileDigest != second.ProfileDigest || len(first.Phases) != 8 {
		t.Fatalf("plan is incomplete or non-deterministic: %#v %#v", first, second)
	}
	inventory := phaseByID(t, first, "inventory")
	hostBaseline := phaseByID(t, first, "host-baseline")
	network := phaseByID(t, first, "network")
	bootstrap := phaseByID(t, first, "bootstrap")
	acceptance := phaseByID(t, first, "acceptance")
	if bootstrap.RollbackRef == "" {
		t.Fatalf("bootstrap phase omits rollback: %#v", bootstrap)
	}
	if len(inventory.InputRefs) != 11 || !contains(inventory.InputRefs, profile.Spec.ProviderAdapterRef) || !contains(inventory.InputRefs, profile.Spec.RegionRef) {
		t.Fatalf("inventory phase must contain the exact three-node provider discovery set: %#v", inventory.InputRefs)
	}
	expectedInventory := []string{profile.Spec.ProviderAdapterRef, profile.Spec.RegionRef}
	for _, node := range profile.Spec.Inventory.Nodes {
		expectedInventory = append(expectedInventory, node.ProviderResourceRef, node.ManagementAddressRef, node.ProvisioningAddressRef)
	}
	slices.Sort(expectedInventory)
	if !slices.Equal(inventory.InputRefs, expectedInventory) {
		t.Fatalf("inventory phase differs from the exact provider discovery set: got=%#v want=%#v", inventory.InputRefs, expectedInventory)
	}
	for _, ref := range []string{profile.Spec.HostRuntimeBaseline.PersistenceRef, profile.Spec.HostRuntimeBaseline.VerificationRef} {
		if contains(inventory.InputRefs, ref) {
			t.Fatalf("inventory phase contains host baseline reference %q: %#v", ref, inventory.InputRefs)
		}
		if countValue(hostBaseline.InputRefs, ref) != 1 {
			t.Fatalf("host-baseline phase omits reference %q: %#v", ref, hostBaseline.InputRefs)
		}
	}
	if len(hostBaseline.InputRefs) != 2 || !slices.Equal(hostBaseline.DependsOn, []string{"inventory"}) || !contains(bootstrap.DependsOn, "host-baseline") {
		t.Fatalf("host baseline is not an isolated bootstrap prerequisite: host=%#v bootstrap=%#v", hostBaseline, bootstrap)
	}
	for _, ref := range []string{
		profile.Spec.Network.ControlPlaneAPIHA.EndpointRef,
		profile.Spec.Network.ControlPlaneAPIHA.IPv4AddressRef,
		profile.Spec.Network.ControlPlaneAPIHA.IPv6AddressRef,
		profile.Spec.Network.ControlPlaneAPIHA.ControlPlaneTransportDeviceRef,
		profile.Spec.Network.ControlPlaneAPIHA.HealthCheckRef,
		profile.Spec.Network.ControlPlaneAPIHA.FailoverPolicyRef,
		profile.Spec.Network.PublicIngressHA.IPv4AddressRef,
		profile.Spec.Network.PublicIngressHA.IPv6AddressRef,
		profile.Spec.Network.PublicIngressHA.HealthCheckRef,
		profile.Spec.Network.PublicIngressHA.FailoverPolicyRef,
	} {
		if countValue(network.InputRefs, ref) != 1 {
			t.Fatalf("network phase omits HA ingress reference %q: %#v", ref, network.InputRefs)
		}
	}
	for _, ref := range append(
		append([]string{}, profile.Spec.Network.ControlPlaneAPIHA.ServingCertificateSANRefs...),
		profile.Spec.Network.ControlPlaneAPIHA.CNIDeviceRefs...,
	) {
		if countValue(network.InputRefs, ref) != 1 {
			t.Fatalf("network phase must contain reference %q exactly once: %#v", ref, network.InputRefs)
		}
	}
	lifecycle := profile.Spec.Network.ControlPlaneAPIHA.ServingCertificateLifecycle
	for _, ref := range []string{lifecycle.ReconfigurationPlanRef, lifecycle.RollbackPlanRef} {
		if countValue(bootstrap.InputRefs, ref) != 1 {
			t.Fatalf("bootstrap phase omits certificate lifecycle reference %q: %#v", ref, bootstrap.InputRefs)
		}
	}
	if countValue(acceptance.InputRefs, lifecycle.OneServerLossAcceptanceRef) != 1 {
		t.Fatalf("acceptance phase omits one-server-loss reference: %#v", acceptance.InputRefs)
	}
}

func TestProfileFailsClosedOnRequiredProductionInputs(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
		blocker     string
	}{
		{name: "single stack", old: "dualStack: true", replacement: "dualStack: false", blocker: "dual_stack_network"},
		{name: "missing dual-stack API IPv6", old: "ipv6AddressRef: networks.control-plane-api.ipv6", replacement: "ipv6AddressRef: ''", blocker: "control_plane_api_ha"},
		{name: "missing control-plane transport device", old: "controlPlaneTransportDeviceRef: network-devices.control-plane-transport", replacement: "controlPlaneTransportDeviceRef: ''", blocker: "control_plane_api_ha"},
		{name: "missing control-plane health check", old: "healthCheckRef: networks.control-plane-api.health-check", replacement: "healthCheckRef: ''", blocker: "control_plane_api_ha"},
		{name: "missing certificate reconfiguration", old: "reconfigurationPlanRef: operations.control-plane-api-certificate.reconfigure", replacement: "reconfigurationPlanRef: ''", blocker: "control_plane_api_ha"},
		{name: "missing certificate rollback", old: "rollbackPlanRef: operations.control-plane-api-certificate.rollback", replacement: "rollbackPlanRef: ''", blocker: "control_plane_api_ha"},
		{name: "missing one-server-loss acceptance", old: "oneServerLossAcceptanceRef: resilience.control-plane-api-one-server-loss", replacement: "oneServerLossAcceptanceRef: ''", blocker: "control_plane_api_ha"},
		{name: "DNS round robin ingress", old: "publicIngressHA:\n      mode: l2-vip", replacement: "publicIngressHA:\n      mode: dns-round-robin", blocker: "public_ingress_ha"},
		{name: "missing ingress health check", old: "healthCheckRef: networks.ingress.health-check", replacement: "healthCheckRef: ''", blocker: "public_ingress_ha"},
		{name: "weak inotify capacity", old: "inotifyMaxUserInstances: 1024", replacement: "inotifyMaxUserInstances: 128", blocker: "host_runtime_baseline"},
		{name: "missing host persistence", old: "persistenceRef: host-baseline.inotify-persistence", replacement: "persistenceRef: ''", blocker: "host_runtime_baseline"},
		{name: "no immutable backup", old: "offCellBackup: true", replacement: "offCellBackup: false", blocker: "snapshot_and_off_cell_storage"},
		{name: "no rollback", old: "rollbackPlanRef: operations.rollback", replacement: "rollbackPlanRef: ''", blocker: "bootstrap_upgrade_rollback"},
		{name: "weak gateway availability", old: "minimumGatewayNodes: 3", replacement: "minimumGatewayNodes: 2", blocker: "availability_policy"},
		{name: "weak availability", old: "minimumFailureDomains: 3", replacement: "minimumFailureDomains: 2", blocker: "availability_policy"},
		{name: "unsafe reference", old: "regionRef: regions.synthetic", replacement: "regionRef: regions..synthetic", blocker: "provider_binding"},
		{name: "readiness overclaim", old: "nonClaim: preflight-and-plan-only", replacement: "nonClaim: production-ready", blocker: "readiness_non_claim"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := parseFixture(t, strings.Replace(validProfileYAML, test.old, test.replacement, 1))
			report := Validate(profile)
			if report.Status != "blocked" || !contains(report.Blockers, test.blocker) {
				t.Fatalf("missing blocker %q: %#v", test.blocker, report)
			}
			if _, err := BuildPlan(profile); !errors.Is(err, ErrProfileBlocked) {
				t.Fatalf("blocked profile produced a plan: %v", err)
			}
		})
	}
}

func TestControlPlaneAPIHARejectsUnsafeBindings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Profile)
	}{
		{
			name: "CNI endpoint mismatch",
			mutate: func(profile *Profile) {
				profile.Spec.Network.ControlPlaneAPIHA.CNIBootstrapEndpointRef = "networks.control-plane-api.other"
			},
		},
		{
			name: "node-bound endpoint",
			mutate: func(profile *Profile) {
				nodeAddress := profile.Spec.Inventory.Nodes[0].ManagementAddressRef
				ha := &profile.Spec.Network.ControlPlaneAPIHA
				ha.EndpointRef = nodeAddress
				ha.CNIBootstrapEndpointRef = nodeAddress
				ha.ServingCertificateSANRefs[0] = nodeAddress
			},
		},
		{
			name: "node-bound IPv4",
			mutate: func(profile *Profile) {
				nodeAddress := profile.Spec.Inventory.Nodes[0].ProvisioningAddressRef
				profile.Spec.Network.ControlPlaneAPIHA.IPv4AddressRef = nodeAddress
				profile.Spec.Network.ControlPlaneAPIHA.ServingCertificateSANRefs[1] = nodeAddress
			},
		},
		{
			name: "node-bound IPv6",
			mutate: func(profile *Profile) {
				nodeAddress := profile.Spec.Inventory.Nodes[0].ManagementAddressRef
				profile.Spec.Network.ControlPlaneAPIHA.IPv6AddressRef = nodeAddress
				profile.Spec.Network.ControlPlaneAPIHA.ServingCertificateSANRefs[2] = nodeAddress
			},
		},
		{
			name: "same IPv4 and IPv6 reference",
			mutate: func(profile *Profile) {
				ha := &profile.Spec.Network.ControlPlaneAPIHA
				ha.IPv6AddressRef = ha.IPv4AddressRef
				ha.ServingCertificateSANRefs = ha.ServingCertificateSANRefs[:2]
			},
		},
		{
			name: "two SANs when endpoint and IPv4 share a reference",
			mutate: func(profile *Profile) {
				ha := &profile.Spec.Network.ControlPlaneAPIHA
				ha.EndpointRef = ha.IPv4AddressRef
				ha.CNIBootstrapEndpointRef = ha.IPv4AddressRef
				ha.ServingCertificateSANRefs = []string{ha.IPv4AddressRef, ha.IPv6AddressRef}
			},
		},
		{
			name: "serving certificate omits IPv6",
			mutate: func(profile *Profile) {
				profile.Spec.Network.ControlPlaneAPIHA.ServingCertificateSANRefs[2] = "networks.control-plane-api.other"
			},
		},
		{
			name: "duplicate serving certificate SAN",
			mutate: func(profile *Profile) {
				ha := &profile.Spec.Network.ControlPlaneAPIHA
				ha.ServingCertificateSANRefs[2] = ha.ServingCertificateSANRefs[1]
			},
		},
		{
			name: "invalid serving certificate SAN",
			mutate: func(profile *Profile) {
				profile.Spec.Network.ControlPlaneAPIHA.ServingCertificateSANRefs[2] = "networks..invalid"
			},
		},
		{
			name: "CNI omits control-plane transport device",
			mutate: func(profile *Profile) {
				profile.Spec.Network.ControlPlaneAPIHA.CNIDeviceRefs = []string{"network-devices.public"}
			},
		},
		{
			name: "duplicate CNI device",
			mutate: func(profile *Profile) {
				profile.Spec.Network.ControlPlaneAPIHA.CNIDeviceRefs = []string{"network-devices.public", "network-devices.public"}
			},
		},
		{
			name: "invalid CNI device",
			mutate: func(profile *Profile) {
				profile.Spec.Network.ControlPlaneAPIHA.CNIDeviceRefs[0] = "network-devices..invalid"
			},
		},
		{
			name: "parallel certificate rollout",
			mutate: func(profile *Profile) {
				profile.Spec.Network.ControlPlaneAPIHA.ServingCertificateLifecycle.RolloutStrategy = "parallel"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := parseFixture(t, validProfileYAML)
			test.mutate(&profile)
			report := Validate(profile)
			if report.Status != "blocked" || !contains(report.Blockers, "control_plane_api_ha") {
				t.Fatalf("unsafe control-plane API HA binding passed validation: %#v", report)
			}
		})
	}
}

func TestInventoryRequiresGatewayRoleAcrossDeclaredFailureDomains(t *testing.T) {
	profile := parseFixture(t, validProfileYAML)
	profile.Spec.Inventory.Nodes[2].Roles = []string{"control-plane", "worker"}

	report := Validate(profile)
	if report.Status != "blocked" || !contains(report.Blockers, "inventory") {
		t.Fatalf("two-node Gateway inventory passed HA validation: %#v", report)
	}
}

func TestInventoryRejectsGatewayNodesInOneFailureDomain(t *testing.T) {
	profile := parseFixture(t, validProfileYAML)
	profile.Spec.Inventory.Nodes[1].Roles = []string{"control-plane", "worker"}
	profile.Spec.Inventory.Nodes[2].Roles = []string{"control-plane", "worker"}
	profile.Spec.Inventory.Nodes = append(profile.Spec.Inventory.Nodes,
		Node{
			ID: "gateway-b", FailureDomain: "zone-a", Roles: []string{"gateway"},
			ProviderResourceRef: "inventory.nodes.gateway-b", ManagementAddressRef: "inventory.addresses.gateway-b.management",
			ProvisioningAddressRef: "inventory.addresses.gateway-b.provisioning",
		},
		Node{
			ID: "gateway-c", FailureDomain: "zone-a", Roles: []string{"gateway"},
			ProviderResourceRef: "inventory.nodes.gateway-c", ManagementAddressRef: "inventory.addresses.gateway-c.management",
			ProvisioningAddressRef: "inventory.addresses.gateway-c.provisioning",
		},
	)

	report := Validate(profile)
	if report.Status != "blocked" || !contains(report.Blockers, "inventory") {
		t.Fatalf("single-domain Gateway inventory passed HA validation: %#v", report)
	}
}

func TestInventoryRequiresCriticalRolesAcrossDeclaredFailureDomains(t *testing.T) {
	profile := parseFixture(t, validProfileYAML)
	for index := range profile.Spec.Inventory.Nodes {
		profile.Spec.Inventory.Nodes[index].FailureDomain = "zone-a"
	}
	profile.Spec.Inventory.Nodes = append(profile.Spec.Inventory.Nodes,
		Node{
			ID:                     "gateway-b",
			FailureDomain:          "zone-b",
			Roles:                  []string{"gateway"},
			ProviderResourceRef:    "inventory.nodes.gateway-b",
			ManagementAddressRef:   "inventory.addresses.gateway-b.management",
			ProvisioningAddressRef: "inventory.addresses.gateway-b.provisioning",
		},
		Node{
			ID:                     "gateway-c",
			FailureDomain:          "zone-c",
			Roles:                  []string{"gateway"},
			ProviderResourceRef:    "inventory.nodes.gateway-c",
			ManagementAddressRef:   "inventory.addresses.gateway-c.management",
			ProvisioningAddressRef: "inventory.addresses.gateway-c.provisioning",
		},
	)

	report := Validate(profile)
	if report.Status != "blocked" || !contains(report.Blockers, "inventory") {
		t.Fatalf("gateway-only domains satisfied critical-role HA: %#v", report)
	}
}

func TestInventoryRejectsDuplicateProviderAndAddressReferences(t *testing.T) {
	tests := []struct {
		name string
		copy func(nodes []Node)
	}{
		{name: "provider resource", copy: func(nodes []Node) { nodes[1].ProviderResourceRef = nodes[0].ProviderResourceRef }},
		{name: "management address", copy: func(nodes []Node) { nodes[1].ManagementAddressRef = nodes[0].ManagementAddressRef }},
		{name: "provisioning address", copy: func(nodes []Node) { nodes[1].ProvisioningAddressRef = nodes[0].ProvisioningAddressRef }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := parseFixture(t, validProfileYAML)
			test.copy(profile.Spec.Inventory.Nodes)
			report := Validate(profile)
			if report.Status != "blocked" || !contains(report.Blockers, "inventory") {
				t.Fatalf("duplicate reference passed inventory validation: %#v", report)
			}
		})
	}
}

func TestInvalidProfileNameIsNotEchoedInBlockedReport(t *testing.T) {
	profile := parseFixture(t, validProfileYAML)
	profile.Metadata.Name = "invalid_name"
	report := Validate(profile)
	if report.Status != "blocked" || report.ProfileName != "" || !contains(report.Blockers, "profile_identity") {
		t.Fatalf("invalid profile identity was echoed or accepted: %#v", report)
	}
}

func TestParserRejectsUnknownDuplicateAliasAndTrailingDocuments(t *testing.T) {
	tests := []string{
		strings.Replace(validProfileYAML, "siteClass: synthetic", "siteClass: synthetic\n  unknownField: rejected", 1),
		strings.Replace(validProfileYAML, "kind: ProviderSiteProfile", "kind: ProviderSiteProfile\nkind: ProviderSiteProfile", 1),
		strings.Replace(validProfileYAML, "name: synthetic-provider-site", "name: &site synthetic-provider-site", 1),
		validProfileYAML + "\n---\n{}\n",
	}
	for index, fixture := range tests {
		if _, err := Parse(strings.NewReader(fixture)); !errors.Is(err, ErrInvalidProfile) {
			t.Fatalf("fixture %d was accepted: %v", index, err)
		}
	}
}

func TestParserRejectsOversizedInput(t *testing.T) {
	if _, err := Parse(bytes.NewReader(bytes.Repeat([]byte{'x'}, maximumBytes+1))); !errors.Is(err, ErrProfileTooLarge) {
		t.Fatalf("oversized profile was accepted: %v", err)
	}
}

func parseFixture(t *testing.T, fixture string) Profile {
	t.Helper()
	profile, err := Parse(strings.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func countValue(values []string, expected string) int {
	count := 0
	for _, value := range values {
		if value == expected {
			count++
		}
	}
	return count
}

func phaseByID(t *testing.T, plan Plan, id string) Phase {
	t.Helper()
	for _, phase := range plan.Phases {
		if phase.ID == id {
			return phase
		}
	}
	t.Fatalf("plan omits phase %q: %#v", id, plan.Phases)
	return Phase{}
}

const validProfileYAML = `apiVersion: cloudring.io/v1alpha1
kind: ProviderSiteProfile
metadata:
  name: synthetic-provider-site
spec:
  providerAdapterRef: adapters.synthetic
  siteClass: synthetic
  regionRef: regions.synthetic
  availability:
    minimumControlPlaneNodes: 3
    minimumWorkerNodes: 3
    minimumGatewayNodes: 3
    minimumFailureDomains: 3
  inventory:
    nodes:
      - id: node-a
        failureDomain: zone-a
        roles: [control-plane, worker, gateway]
        providerResourceRef: inventory.nodes.node-a
        managementAddressRef: inventory.addresses.node-a.management
        provisioningAddressRef: inventory.addresses.node-a.provisioning
      - id: node-b
        failureDomain: zone-b
        roles: [control-plane, worker, gateway]
        providerResourceRef: inventory.nodes.node-b
        managementAddressRef: inventory.addresses.node-b.management
        provisioningAddressRef: inventory.addresses.node-b.provisioning
      - id: node-c
        failureDomain: zone-c
        roles: [control-plane, worker, gateway]
        providerResourceRef: inventory.nodes.node-c
        managementAddressRef: inventory.addresses.node-c.management
        provisioningAddressRef: inventory.addresses.node-c.provisioning
  network:
    dualStack: true
    managementPlaneRef: networks.management
    provisioningPlaneRef: networks.provisioning
    tenantPlaneRef: networks.tenant
    publicIngressRef: networks.ingress
    controlPlaneAPIHA:
      mode: l2-vip
      endpointRef: networks.control-plane-api.endpoint
      ipv4AddressRef: networks.control-plane-api.ipv4
      ipv6AddressRef: networks.control-plane-api.ipv6
      servingCertificateSANRefs:
        - networks.control-plane-api.endpoint
        - networks.control-plane-api.ipv4
        - networks.control-plane-api.ipv6
      cniBootstrapEndpointRef: networks.control-plane-api.endpoint
      controlPlaneTransportDeviceRef: network-devices.control-plane-transport
      cniDeviceRefs:
        - network-devices.public
        - network-devices.control-plane-transport
      healthCheckRef: networks.control-plane-api.health-check
      failoverPolicyRef: networks.control-plane-api.failover
      servingCertificateLifecycle:
        rolloutStrategy: one-node-at-a-time
        reconfigurationPlanRef: operations.control-plane-api-certificate.reconfigure
        rollbackPlanRef: operations.control-plane-api-certificate.rollback
        oneServerLossAcceptanceRef: resilience.control-plane-api-one-server-loss
    publicIngressHA:
      mode: l2-vip
      ipv4AddressRef: networks.ingress.ipv4
      ipv6AddressRef: networks.ingress.ipv6
      healthCheckRef: networks.ingress.health-check
      failoverPolicyRef: networks.ingress.failover
  hostRuntimeBaseline:
    inotifyMaxUserInstances: 1024
    persistenceRef: host-baseline.inotify-persistence
    verificationRef: host-baseline.kubevirt-device-plugins
  storage:
    defaultClassRef: storage.default
    snapshotClassRef: storage.snapshots
    backupLocationRef: backup.off-cell
    immutableRetentionPolicyRef: backup.retention
    offCellBackup: true
  identity:
    oidcProviderRef: identity.oidc
    workloadIdentityRef: identity.workload
    runtimeInputBrokerRef: runtime-inputs.platform
  operations:
    gitOpsSourceRef: gitops.platform
    bootstrapPlanRef: operations.bootstrap
    upgradePlanRef: operations.upgrade
    rollbackPlanRef: operations.rollback
  observability:
    metricsRef: observability.metrics
    logsRef: observability.logs
    tracesRef: observability.traces
    alertsRef: observability.alerts
  ocs:
    version: v3
    conformanceProfileRef: ocs.provider-conformance
  nonClaim: preflight-and-plan-only
`
