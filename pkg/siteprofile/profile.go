// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Package siteprofile validates provider-neutral site inventory and renders a
// deterministic installation plan. It deliberately does not apply resources.
package siteprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	APIVersion       = "cloudring.io/v1alpha1"
	Kind             = "ProviderSiteProfile"
	PlanSchema       = "cloudring.site-plan/v1alpha1"
	RequiredNonClaim = "preflight-and-plan-only"
	maximumBytes     = 1 << 20
	maximumYAMLNodes = 4096
)

var (
	ErrInvalidProfile  = errors.New("invalid provider site profile")
	ErrProfileTooLarge = errors.New("provider site profile exceeds size limit")
	ErrProfileBlocked  = errors.New("provider site profile is blocked")
	namePattern        = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
	referencePattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._/-][a-z0-9]+)*$`)
)

type Profile struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       Spec     `json:"spec" yaml:"spec"`
}

type Metadata struct {
	Name string `json:"name" yaml:"name"`
}

type Spec struct {
	ProviderAdapterRef  string              `json:"providerAdapterRef" yaml:"providerAdapterRef"`
	SiteClass           string              `json:"siteClass" yaml:"siteClass"`
	RegionRef           string              `json:"regionRef" yaml:"regionRef"`
	Availability        Availability        `json:"availability" yaml:"availability"`
	Inventory           Inventory           `json:"inventory" yaml:"inventory"`
	Network             Network             `json:"network" yaml:"network"`
	HostRuntimeBaseline HostRuntimeBaseline `json:"hostRuntimeBaseline" yaml:"hostRuntimeBaseline"`
	Storage             Storage             `json:"storage" yaml:"storage"`
	Identity            Identity            `json:"identity" yaml:"identity"`
	Operations          Operations          `json:"operations" yaml:"operations"`
	Observability       Observability       `json:"observability" yaml:"observability"`
	OCS                 OCS                 `json:"ocs" yaml:"ocs"`
	NonClaim            string              `json:"nonClaim" yaml:"nonClaim"`
}

type Availability struct {
	MinimumControlPlaneNodes int `json:"minimumControlPlaneNodes" yaml:"minimumControlPlaneNodes"`
	MinimumWorkerNodes       int `json:"minimumWorkerNodes" yaml:"minimumWorkerNodes"`
	MinimumGatewayNodes      int `json:"minimumGatewayNodes" yaml:"minimumGatewayNodes"`
	MinimumFailureDomains    int `json:"minimumFailureDomains" yaml:"minimumFailureDomains"`
}

type Inventory struct {
	Nodes []Node `json:"nodes" yaml:"nodes"`
}

type Node struct {
	ID                     string   `json:"id" yaml:"id"`
	FailureDomain          string   `json:"failureDomain" yaml:"failureDomain"`
	Roles                  []string `json:"roles" yaml:"roles"`
	ProviderResourceRef    string   `json:"providerResourceRef" yaml:"providerResourceRef"`
	ManagementAddressRef   string   `json:"managementAddressRef" yaml:"managementAddressRef"`
	ProvisioningAddressRef string   `json:"provisioningAddressRef" yaml:"provisioningAddressRef"`
}

type Network struct {
	DualStack            bool              `json:"dualStack" yaml:"dualStack"`
	ManagementPlaneRef   string            `json:"managementPlaneRef" yaml:"managementPlaneRef"`
	ProvisioningPlaneRef string            `json:"provisioningPlaneRef" yaml:"provisioningPlaneRef"`
	TenantPlaneRef       string            `json:"tenantPlaneRef" yaml:"tenantPlaneRef"`
	PublicIngressRef     string            `json:"publicIngressRef" yaml:"publicIngressRef"`
	ControlPlaneAPIHA    ControlPlaneAPIHA `json:"controlPlaneAPIHA" yaml:"controlPlaneAPIHA"`
	PublicIngressHA      PublicIngressHA   `json:"publicIngressHA" yaml:"publicIngressHA"`
}

// ControlPlaneAPIHA binds both the kubeadm endpoint and every component which
// needs the API before Kubernetes Service routing exists to the same
// health-checked endpoint. A node management or provisioning address is not a
// control-plane HA endpoint.
type ControlPlaneAPIHA struct {
	Mode                           string                      `json:"mode" yaml:"mode"`
	EndpointRef                    string                      `json:"endpointRef" yaml:"endpointRef"`
	IPv4AddressRef                 string                      `json:"ipv4AddressRef" yaml:"ipv4AddressRef"`
	IPv6AddressRef                 string                      `json:"ipv6AddressRef" yaml:"ipv6AddressRef"`
	ServingCertificateSANRefs      []string                    `json:"servingCertificateSANRefs" yaml:"servingCertificateSANRefs"`
	CNIBootstrapEndpointRef        string                      `json:"cniBootstrapEndpointRef" yaml:"cniBootstrapEndpointRef"`
	ControlPlaneTransportDeviceRef string                      `json:"controlPlaneTransportDeviceRef" yaml:"controlPlaneTransportDeviceRef"`
	CNIDeviceRefs                  []string                    `json:"cniDeviceRefs" yaml:"cniDeviceRefs"`
	HealthCheckRef                 string                      `json:"healthCheckRef" yaml:"healthCheckRef"`
	FailoverPolicyRef              string                      `json:"failoverPolicyRef" yaml:"failoverPolicyRef"`
	ServingCertificateLifecycle    ServingCertificateLifecycle `json:"servingCertificateLifecycle" yaml:"servingCertificateLifecycle"`
}

// ServingCertificateLifecycle binds a fail-closed rolling reconfiguration to
// its rollback and the failure exercise which proves the shared endpoint.
type ServingCertificateLifecycle struct {
	RolloutStrategy            string `json:"rolloutStrategy" yaml:"rolloutStrategy"`
	ReconfigurationPlanRef     string `json:"reconfigurationPlanRef" yaml:"reconfigurationPlanRef"`
	RollbackPlanRef            string `json:"rollbackPlanRef" yaml:"rollbackPlanRef"`
	OneServerLossAcceptanceRef string `json:"oneServerLossAcceptanceRef" yaml:"oneServerLossAcceptanceRef"`
}

// PublicIngressHA describes stable dual-stack service addresses and the
// provider-owned mechanisms that keep them healthy during a failure-domain
// loss. DNS round robin over node addresses is deliberately not a valid mode.
type PublicIngressHA struct {
	Mode              string `json:"mode" yaml:"mode"`
	IPv4AddressRef    string `json:"ipv4AddressRef" yaml:"ipv4AddressRef"`
	IPv6AddressRef    string `json:"ipv6AddressRef" yaml:"ipv6AddressRef"`
	HealthCheckRef    string `json:"healthCheckRef" yaml:"healthCheckRef"`
	FailoverPolicyRef string `json:"failoverPolicyRef" yaml:"failoverPolicyRef"`
}

// HostRuntimeBaseline declares the minimum portable host capacity needed by
// the container and virtualization runtimes. Downstream installers own the
// operating-system-specific persistence and verification implementations.
type HostRuntimeBaseline struct {
	InotifyMaxUserInstances int    `json:"inotifyMaxUserInstances" yaml:"inotifyMaxUserInstances"`
	PersistenceRef          string `json:"persistenceRef" yaml:"persistenceRef"`
	VerificationRef         string `json:"verificationRef" yaml:"verificationRef"`
}

type Storage struct {
	DefaultClassRef             string `json:"defaultClassRef" yaml:"defaultClassRef"`
	SnapshotClassRef            string `json:"snapshotClassRef" yaml:"snapshotClassRef"`
	BackupLocationRef           string `json:"backupLocationRef" yaml:"backupLocationRef"`
	ImmutableRetentionPolicyRef string `json:"immutableRetentionPolicyRef" yaml:"immutableRetentionPolicyRef"`
	OffCellBackup               bool   `json:"offCellBackup" yaml:"offCellBackup"`
}

type Identity struct {
	OIDCProviderRef       string `json:"oidcProviderRef" yaml:"oidcProviderRef"`
	WorkloadIdentityRef   string `json:"workloadIdentityRef" yaml:"workloadIdentityRef"`
	RuntimeInputBrokerRef string `json:"runtimeInputBrokerRef" yaml:"runtimeInputBrokerRef"`
}

type Operations struct {
	GitOpsSourceRef  string `json:"gitOpsSourceRef" yaml:"gitOpsSourceRef"`
	BootstrapPlanRef string `json:"bootstrapPlanRef" yaml:"bootstrapPlanRef"`
	UpgradePlanRef   string `json:"upgradePlanRef" yaml:"upgradePlanRef"`
	RollbackPlanRef  string `json:"rollbackPlanRef" yaml:"rollbackPlanRef"`
}

type Observability struct {
	MetricsRef string `json:"metricsRef" yaml:"metricsRef"`
	LogsRef    string `json:"logsRef" yaml:"logsRef"`
	TracesRef  string `json:"tracesRef" yaml:"tracesRef"`
	AlertsRef  string `json:"alertsRef" yaml:"alertsRef"`
}

type OCS struct {
	Version               string `json:"version" yaml:"version"`
	ConformanceProfileRef string `json:"conformanceProfileRef" yaml:"conformanceProfileRef"`
}

type Report struct {
	Status        string   `json:"status"`
	ProfileName   string   `json:"profileName,omitempty"`
	ProfileDigest string   `json:"profileDigest,omitempty"`
	Checks        []Check  `json:"checks"`
	Blockers      []string `json:"blockers,omitempty"`
	NonClaim      string   `json:"nonClaim"`
}

type Check struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type Plan struct {
	SchemaVersion string  `json:"schemaVersion"`
	ProfileName   string  `json:"profileName"`
	ProfileDigest string  `json:"profileDigest"`
	Phases        []Phase `json:"phases"`
	NonClaim      string  `json:"nonClaim"`
}

type Phase struct {
	ID          string   `json:"id"`
	DependsOn   []string `json:"dependsOn"`
	InputRefs   []string `json:"inputRefs"`
	Mutation    bool     `json:"mutation"`
	RollbackRef string   `json:"rollbackRef,omitempty"`
}

func Parse(reader io.Reader) (Profile, error) {
	if reader == nil {
		return Profile{}, ErrInvalidProfile
	}
	data, err := io.ReadAll(io.LimitReader(reader, maximumBytes+1))
	if err != nil {
		return Profile{}, ErrInvalidProfile
	}
	if len(data) > maximumBytes {
		return Profile{}, ErrProfileTooLarge
	}
	if err := validateYAMLShape(data); err != nil {
		return Profile{}, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var profile Profile
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, ErrInvalidProfile
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Profile{}, ErrInvalidProfile
	}
	return profile, nil
}

func validateYAMLShape(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return ErrInvalidProfile
	}
	count := 0
	var walk func(*yaml.Node) error
	walk = func(node *yaml.Node) error {
		if node == nil {
			return ErrInvalidProfile
		}
		count++
		if count > maximumYAMLNodes || node.Kind == yaml.AliasNode || node.Anchor != "" {
			return ErrInvalidProfile
		}
		for _, child := range node.Content {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(&document)
}

func Validate(profile Profile) Report {
	report := Report{
		Status:   "ready",
		Checks:   []Check{},
		NonClaim: RequiredNonClaim,
	}
	if validName(profile.Metadata.Name) {
		report.ProfileName = profile.Metadata.Name
	}
	report.ProfileDigest = digestProfile(profile)
	record := func(id string, passed bool) {
		status := "pass"
		if !passed {
			status = "blocked"
			report.Status = "blocked"
			report.Blockers = append(report.Blockers, id)
		}
		report.Checks = append(report.Checks, Check{ID: id, Status: status})
	}

	record("profile_identity", profile.APIVersion == APIVersion && profile.Kind == Kind && validName(profile.Metadata.Name))
	record("provider_binding", validRef(profile.Spec.ProviderAdapterRef) && validName(profile.Spec.SiteClass) && validRef(profile.Spec.RegionRef))
	record("availability_policy", validAvailability(profile.Spec.Availability))
	record("inventory", validInventory(profile.Spec.Inventory, profile.Spec.Availability))
	record("dual_stack_network", profile.Spec.Network.DualStack && allRefs(
		profile.Spec.Network.ManagementPlaneRef,
		profile.Spec.Network.ProvisioningPlaneRef,
		profile.Spec.Network.TenantPlaneRef,
		profile.Spec.Network.PublicIngressRef,
	))
	record("control_plane_api_ha", validControlPlaneAPIHA(
		profile.Spec.Network.ControlPlaneAPIHA,
		profile.Spec.Inventory,
	))
	record("public_ingress_ha", validPublicIngressHA(profile.Spec.Network.PublicIngressHA))
	record("host_runtime_baseline", profile.Spec.HostRuntimeBaseline.InotifyMaxUserInstances >= 1024 && allRefs(
		profile.Spec.HostRuntimeBaseline.PersistenceRef,
		profile.Spec.HostRuntimeBaseline.VerificationRef,
	))
	record("snapshot_and_off_cell_storage", profile.Spec.Storage.OffCellBackup && allRefs(
		profile.Spec.Storage.DefaultClassRef,
		profile.Spec.Storage.SnapshotClassRef,
		profile.Spec.Storage.BackupLocationRef,
		profile.Spec.Storage.ImmutableRetentionPolicyRef,
	))
	record("identity_and_secret_store", allRefs(
		profile.Spec.Identity.OIDCProviderRef,
		profile.Spec.Identity.WorkloadIdentityRef,
		profile.Spec.Identity.RuntimeInputBrokerRef,
	))
	record("bootstrap_upgrade_rollback", allRefs(
		profile.Spec.Operations.GitOpsSourceRef,
		profile.Spec.Operations.BootstrapPlanRef,
		profile.Spec.Operations.UpgradePlanRef,
		profile.Spec.Operations.RollbackPlanRef,
	))
	record("observability", allRefs(
		profile.Spec.Observability.MetricsRef,
		profile.Spec.Observability.LogsRef,
		profile.Spec.Observability.TracesRef,
		profile.Spec.Observability.AlertsRef,
	))
	record("ocs_conformance", profile.Spec.OCS.Version == "v3" && validRef(profile.Spec.OCS.ConformanceProfileRef))
	record("readiness_non_claim", profile.Spec.NonClaim == RequiredNonClaim)
	return report
}

func BuildPlan(profile Profile) (Plan, error) {
	report := Validate(profile)
	if report.Status != "ready" {
		return Plan{}, ErrProfileBlocked
	}
	nodeRefs := make([]string, 0, len(profile.Spec.Inventory.Nodes)*3+2)
	nodeRefs = append(nodeRefs,
		profile.Spec.ProviderAdapterRef,
		profile.Spec.RegionRef,
	)
	for _, node := range profile.Spec.Inventory.Nodes {
		nodeRefs = append(nodeRefs, node.ProviderResourceRef, node.ManagementAddressRef, node.ProvisioningAddressRef)
	}
	sort.Strings(nodeRefs)
	return Plan{
		SchemaVersion: PlanSchema,
		ProfileName:   profile.Metadata.Name,
		ProfileDigest: report.ProfileDigest,
		NonClaim:      RequiredNonClaim,
		Phases: []Phase{
			{ID: "inventory", DependsOn: []string{}, InputRefs: nodeRefs, Mutation: false},
			{ID: "host-baseline", DependsOn: []string{"inventory"}, InputRefs: sortedRefs(
				profile.Spec.HostRuntimeBaseline.PersistenceRef,
				profile.Spec.HostRuntimeBaseline.VerificationRef,
			), Mutation: false},
			{ID: "network", DependsOn: []string{"inventory"}, InputRefs: networkInputRefs(profile), Mutation: false},
			{ID: "identity", DependsOn: []string{"inventory", "network"}, InputRefs: sortedRefs(
				profile.Spec.Identity.OIDCProviderRef,
				profile.Spec.Identity.WorkloadIdentityRef,
				profile.Spec.Identity.RuntimeInputBrokerRef,
			), Mutation: false},
			{ID: "storage", DependsOn: []string{"inventory", "network", "identity"}, InputRefs: sortedRefs(
				profile.Spec.Storage.DefaultClassRef,
				profile.Spec.Storage.SnapshotClassRef,
				profile.Spec.Storage.BackupLocationRef,
				profile.Spec.Storage.ImmutableRetentionPolicyRef,
			), Mutation: false},
			{ID: "observability", DependsOn: []string{"inventory", "network"}, InputRefs: sortedRefs(
				profile.Spec.Observability.MetricsRef,
				profile.Spec.Observability.LogsRef,
				profile.Spec.Observability.TracesRef,
				profile.Spec.Observability.AlertsRef,
			), Mutation: false},
			{ID: "bootstrap", DependsOn: []string{"host-baseline", "identity", "storage", "observability"}, InputRefs: sortedRefs(
				profile.Spec.Operations.GitOpsSourceRef,
				profile.Spec.Operations.BootstrapPlanRef,
				profile.Spec.Network.ControlPlaneAPIHA.ServingCertificateLifecycle.ReconfigurationPlanRef,
				profile.Spec.Network.ControlPlaneAPIHA.ServingCertificateLifecycle.RollbackPlanRef,
			), Mutation: true, RollbackRef: profile.Spec.Operations.RollbackPlanRef},
			{ID: "acceptance", DependsOn: []string{"bootstrap"}, InputRefs: sortedRefs(
				profile.Spec.Operations.UpgradePlanRef,
				profile.Spec.Operations.RollbackPlanRef,
				profile.Spec.OCS.ConformanceProfileRef,
				profile.Spec.Network.ControlPlaneAPIHA.ServingCertificateLifecycle.OneServerLossAcceptanceRef,
			), Mutation: false},
		},
	}, nil
}

func digestProfile(profile Profile) string {
	payload, err := json.Marshal(profile)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func validName(value string) bool {
	return len(value) >= 3 && len(value) <= 63 && namePattern.MatchString(value)
}

func validRef(value string) bool {
	return len(value) >= 3 && len(value) <= 253 && referencePattern.MatchString(value) &&
		!strings.Contains(value, "..") && !strings.Contains(value, "//")
}

func allRefs(values ...string) bool {
	return len(values) > 0 && !slices.ContainsFunc(values, func(value string) bool { return !validRef(value) })
}

func validAvailability(value Availability) bool {
	return value.MinimumControlPlaneNodes >= 3 && value.MinimumWorkerNodes >= 3 &&
		value.MinimumGatewayNodes >= 3 && value.MinimumFailureDomains >= 3
}

func validPublicIngressHA(value PublicIngressHA) bool {
	switch value.Mode {
	case "l2-vip", "bgp-vip", "provider-load-balancer", "anycast":
	default:
		return false
	}
	return allRefs(value.IPv4AddressRef, value.IPv6AddressRef, value.HealthCheckRef, value.FailoverPolicyRef)
}

func validControlPlaneAPIHA(value ControlPlaneAPIHA, inventory Inventory) bool {
	switch value.Mode {
	case "l2-vip", "bgp-vip", "provider-load-balancer", "anycast":
	default:
		return false
	}
	if !allRefs(
		value.EndpointRef,
		value.IPv4AddressRef,
		value.IPv6AddressRef,
		value.CNIBootstrapEndpointRef,
		value.ControlPlaneTransportDeviceRef,
		value.HealthCheckRef,
		value.FailoverPolicyRef,
	) ||
		value.EndpointRef != value.CNIBootstrapEndpointRef ||
		value.IPv4AddressRef == value.IPv6AddressRef ||
		len(value.ServingCertificateSANRefs) < 3 ||
		!validUniqueRefs(value.ServingCertificateSANRefs) ||
		!containsAll(
			value.ServingCertificateSANRefs,
			value.EndpointRef,
			value.IPv4AddressRef,
			value.IPv6AddressRef,
		) ||
		!validUniqueRefs(value.CNIDeviceRefs) ||
		!slices.Contains(value.CNIDeviceRefs, value.ControlPlaneTransportDeviceRef) ||
		value.ServingCertificateLifecycle.RolloutStrategy != "one-node-at-a-time" ||
		!allRefs(
			value.ServingCertificateLifecycle.ReconfigurationPlanRef,
			value.ServingCertificateLifecycle.RollbackPlanRef,
			value.ServingCertificateLifecycle.OneServerLossAcceptanceRef,
		) {
		return false
	}
	for _, node := range inventory.Nodes {
		if slices.Contains(
			[]string{value.EndpointRef, value.IPv4AddressRef, value.IPv6AddressRef},
			node.ManagementAddressRef,
		) || slices.Contains(
			[]string{value.EndpointRef, value.IPv4AddressRef, value.IPv6AddressRef},
			node.ProvisioningAddressRef,
		) {
			return false
		}
	}
	return true
}

func networkInputRefs(profile Profile) []string {
	network := profile.Spec.Network
	controlPlane := network.ControlPlaneAPIHA
	values := []string{
		network.ManagementPlaneRef,
		network.ProvisioningPlaneRef,
		network.TenantPlaneRef,
		network.PublicIngressRef,
		controlPlane.EndpointRef,
		controlPlane.IPv4AddressRef,
		controlPlane.IPv6AddressRef,
		controlPlane.ControlPlaneTransportDeviceRef,
		controlPlane.HealthCheckRef,
		controlPlane.FailoverPolicyRef,
		network.PublicIngressHA.IPv4AddressRef,
		network.PublicIngressHA.IPv6AddressRef,
		network.PublicIngressHA.HealthCheckRef,
		network.PublicIngressHA.FailoverPolicyRef,
	}
	values = append(values, controlPlane.ServingCertificateSANRefs...)
	values = append(values, controlPlane.CNIDeviceRefs...)
	return sortedRefs(values...)
}

func validUniqueRefs(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validRef(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func containsAll(values []string, expected ...string) bool {
	return !slices.ContainsFunc(expected, func(value string) bool {
		return !slices.Contains(values, value)
	})
}

func validInventory(value Inventory, availability Availability) bool {
	if len(value.Nodes) < max(availability.MinimumControlPlaneNodes, availability.MinimumWorkerNodes, availability.MinimumGatewayNodes) {
		return false
	}
	nodeIDs := map[string]bool{}
	providerResourceRefs := map[string]bool{}
	managementAddressRefs := map[string]bool{}
	provisioningAddressRefs := map[string]bool{}
	controlPlaneFailureDomains := map[string]bool{}
	workerFailureDomains := map[string]bool{}
	gatewayFailureDomains := map[string]bool{}
	controlPlanes, workers, gateways := 0, 0, 0
	allowedRoles := map[string]bool{"control-plane": true, "worker": true, "storage": true, "gateway": true}
	for _, node := range value.Nodes {
		if !validName(node.ID) || !validName(node.FailureDomain) || nodeIDs[node.ID] || len(node.Roles) == 0 ||
			providerResourceRefs[node.ProviderResourceRef] || managementAddressRefs[node.ManagementAddressRef] ||
			provisioningAddressRefs[node.ProvisioningAddressRef] ||
			!allRefs(node.ProviderResourceRef, node.ManagementAddressRef, node.ProvisioningAddressRef) {
			return false
		}
		nodeIDs[node.ID] = true
		providerResourceRefs[node.ProviderResourceRef] = true
		managementAddressRefs[node.ManagementAddressRef] = true
		provisioningAddressRefs[node.ProvisioningAddressRef] = true
		seenRoles := map[string]bool{}
		for _, role := range node.Roles {
			if !allowedRoles[role] || seenRoles[role] {
				return false
			}
			seenRoles[role] = true
		}
		if seenRoles["control-plane"] {
			controlPlanes++
			controlPlaneFailureDomains[node.FailureDomain] = true
		}
		if seenRoles["worker"] {
			workers++
			workerFailureDomains[node.FailureDomain] = true
		}
		if seenRoles["gateway"] {
			gateways++
			gatewayFailureDomains[node.FailureDomain] = true
		}
	}
	return controlPlanes >= availability.MinimumControlPlaneNodes && workers >= availability.MinimumWorkerNodes && gateways >= availability.MinimumGatewayNodes &&
		len(controlPlaneFailureDomains) >= availability.MinimumFailureDomains &&
		len(workerFailureDomains) >= availability.MinimumFailureDomains &&
		len(gatewayFailureDomains) >= availability.MinimumFailureDomains
}

func sortedRefs(values ...string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
