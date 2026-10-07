// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package platformmanifest

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	certManagerProfilePath       = "deploy/kubernetes/cert-manager"
	certManagerVersion           = "v1.21.0"
	certManagerOCIManifestDigest = "sha256:cd55fea42658e54abc25e85a0bc1de229925a5006445f916bfd2c6dc80ac3613"
)

var certManagerImages = map[string]struct {
	repository string
	digest     string
}{
	"controller": {
		repository: "quay.io/jetstack/cert-manager-controller",
		digest:     "sha256:e370f7800a53078e9d74324287a7d52b553864e55f5b4e521f911c3f6c7da203",
	},
	"webhook": {
		repository: "quay.io/jetstack/cert-manager-webhook",
		digest:     "sha256:c33cca307541e2d58861a55b1af5f390b7e19c8741e48b433693b73a7cce88b3",
	},
	"cainjector": {
		repository: "quay.io/jetstack/cert-manager-cainjector",
		digest:     "sha256:ad1dcc5b2fccc420f9b3fbee7ce8a869450c540fd4f2f41de2d95b1ca0c4d701",
	},
	"startupapicheck": {
		repository: "quay.io/jetstack/cert-manager-startupapicheck",
		digest:     "sha256:68b3c5029dc63e64a6b6435337d7dc0eb169f889a48a02d999d1f22f31865b33",
	},
	"acmesolver": {
		repository: "quay.io/jetstack/cert-manager-acmesolver",
		digest:     "sha256:33ebbc2688578e37bd48dcc5b6b1f1362c919dff44fe5e5f602532a2d37d514f",
	},
}

// VerifyCertManager validates the reusable Flux source without treating a
// structural result as live issuance, renewal, or availability evidence.
func VerifyCertManager(root string) (Report, error) {
	root, err := canonicalRoot(root)
	if err != nil {
		return Report{}, err
	}
	report := Report{Status: "blocked", Profile: "cloudring-cert-manager-ha/v1"}
	repository, err := os.OpenRoot(root)
	if err != nil {
		return report, errors.New("open confined repository root")
	}
	defer repository.Close()

	if err := validateSimpleKustomization(repository, filepath.Join(certManagerProfilePath, "controllers", "kustomization.yaml"), "resources.yaml"); err != nil {
		return report, fmt.Errorf("cert-manager controllers stage: %w", err)
	}
	manifest, err := readRegular(repository, filepath.Join(certManagerProfilePath, "controllers", "resources.yaml"))
	if err != nil {
		return report, err
	}
	for _, forbidden := range [][]byte{
		[]byte(":latest"), []byte("REPLACE_WITH"), []byte("example.invalid"),
		[]byte("kind: Secret"), []byte("valuesFrom:"), []byte("postRenderers:"),
	} {
		if bytes.Contains(manifest, forbidden) {
			return report, errors.New("cert-manager source contains mutable, unresolved, secret, or render-time input")
		}
	}
	objects, err := decodeObjects(manifest)
	if err != nil {
		return report, fmt.Errorf("decode cert-manager controllers: %w", err)
	}
	readme, err := readRegular(repository, filepath.Join(certManagerProfilePath, "README.md"))
	if err != nil {
		return report, err
	}
	artifact, err := requireRuntimeChartArtifact(repository, "cert-manager")
	if err != nil || artifact.ManifestDigest != certManagerOCIManifestDigest {
		return report, errors.New("cert-manager reviewed OCI artifact contract is invalid")
	}
	for _, required := range [][]byte{
		[]byte("intentionally suspended"),
		[]byte("does not prove"),
		[]byte("installs no `Issuer` or `ClusterIssuer`"),
		[]byte("issuance and renewal"),
		[]byte("one controller node is unavailable"),
	} {
		if !bytes.Contains(readme, required) {
			return report, errors.New("cert-manager activation and non-claim documentation is incomplete")
		}
	}

	// kustomization, manifest, README, and the shared supply-chain manifest.
	report.Files = 4
	report.Documents = len(objects)
	if report.Documents != 3 {
		return report, errors.New("cert-manager source inventory is incomplete")
	}
	index, err := exactCertManagerInventory(objects)
	if err != nil {
		return report, err
	}
	if err := validateCertManagerNamespace(index["Namespace//cert-manager"].Data); err != nil {
		return report, err
	}
	if err := validateCertManagerOCIRepository(index["OCIRepository/cert-manager/cert-manager"].Data); err != nil {
		return report, err
	}
	if err := validateCertManagerRelease(index["HelmRelease/cert-manager/cert-manager"].Data); err != nil {
		return report, err
	}

	report.Status = "ready"
	report.Checks = []string{
		"source_release_suspended",
		"chart_oci_manifest_and_content_digest_pinned",
		"all_runtime_images_digest_pinned",
		"crd_create_replace_and_retention_ready",
		"controller_webhook_and_cainjector_three_replicas",
		"controller_webhook_and_cainjector_disruption_budgets_ready",
		"hard_host_topology_spread_ready",
		"safe_install_upgrade_rollback_remediation_ready",
		"live_issuance_renewal_webhook_and_one_node_loss_non_claim_preserved",
	}
	return report, nil
}

func exactCertManagerInventory(objects []object) (map[string]object, error) {
	index := make(map[string]object, len(objects))
	for _, item := range objects {
		key := item.Kind + "/" + item.Namespace + "/" + item.Name
		if _, duplicate := index[key]; duplicate {
			return nil, errors.New("duplicate cert-manager manifest object identity")
		}
		index[key] = item
	}
	expected := []string{
		"HelmRelease/cert-manager/cert-manager",
		"Namespace//cert-manager",
		"OCIRepository/cert-manager/cert-manager",
	}
	actual := make([]string, 0, len(index))
	for key := range index {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		return nil, errors.New("cert-manager object inventory is not exact")
	}
	return index, nil
}

func validateCertManagerNamespace(namespace map[string]any) error {
	if nestedString(namespace, "apiVersion") != "v1" ||
		!exactStringMap(nested(namespace, "metadata", "labels"), map[string]string{
			"app.kubernetes.io/part-of":          "cloudring-cert-manager",
			"pod-security.kubernetes.io/enforce": "restricted",
			"pod-security.kubernetes.io/audit":   "restricted",
			"pod-security.kubernetes.io/warn":    "restricted",
		}) {
		return errors.New("cert-manager namespace security boundary is invalid")
	}
	return nil
}

func validateCertManagerOCIRepository(repository map[string]any) error {
	if nestedString(repository, "apiVersion") != "source.toolkit.fluxcd.io/v1" ||
		!exactMappingKeys(nested(repository, "spec"), "interval", "url", "ref", "layerSelector") ||
		nestedString(repository, "spec", "interval") != "1h" ||
		nestedString(repository, "spec", "url") != "oci://quay.io/jetstack/charts/cert-manager" ||
		!exactMappingKeys(nested(repository, "spec", "ref"), "digest") ||
		nestedString(repository, "spec", "ref", "digest") != certManagerOCIManifestDigest ||
		!exactMappingKeys(nested(repository, "spec", "layerSelector"), "mediaType", "operation") ||
		nestedString(repository, "spec", "layerSelector", "mediaType") != "application/vnd.cncf.helm.chart.content.v1.tar+gzip" ||
		nestedString(repository, "spec", "layerSelector", "operation") != "copy" {
		return errors.New("cert-manager OCI chart source is invalid")
	}
	return nil
}

func validateCertManagerRelease(release map[string]any) error {
	if nestedString(release, "apiVersion") != "helm.toolkit.fluxcd.io/v2" ||
		nestedString(release, "metadata", "annotations", "cloudring.org/non-claim") != "downstream-live-issuance-renewal-webhook-and-one-node-loss-evidence-required" ||
		!exactMappingKeys(nested(release, "metadata", "annotations"), "cloudring.org/non-claim") ||
		!exactMappingKeys(nested(release, "spec"), "suspend", "interval", "timeout", "releaseName", "chartRef", "install", "upgrade", "rollback", "driftDetection", "values") ||
		!exactBool(release, true, "spec", "suspend") || nestedString(release, "spec", "interval") != "15m" ||
		nestedString(release, "spec", "timeout") != "10m" || nestedString(release, "spec", "releaseName") != "cert-manager" {
		return errors.New("cert-manager Flux release boundary is invalid")
	}
	chartRef := nested(release, "spec", "chartRef")
	if !exactMappingKeys(chartRef, "kind", "name", "namespace") ||
		nestedString(release, "spec", "chartRef", "kind") != "OCIRepository" ||
		nestedString(release, "spec", "chartRef", "name") != "cert-manager" ||
		nestedString(release, "spec", "chartRef", "namespace") != "cert-manager" {
		return errors.New("cert-manager chart pin is invalid")
	}
	if !exactMappingKeys(nested(release, "spec", "install"), "crds", "remediation") ||
		nestedString(release, "spec", "install", "crds") != "CreateReplace" ||
		!exactMappingKeys(nested(release, "spec", "install", "remediation"), "retries", "remediateLastFailure") ||
		nestedNumber(release, "spec", "install", "remediation", "retries") != 3 ||
		!exactBool(release, true, "spec", "install", "remediation", "remediateLastFailure") ||
		!exactMappingKeys(nested(release, "spec", "upgrade"), "crds", "cleanupOnFail", "remediation") ||
		nestedString(release, "spec", "upgrade", "crds") != "CreateReplace" ||
		!exactBool(release, true, "spec", "upgrade", "cleanupOnFail") ||
		!exactMappingKeys(nested(release, "spec", "upgrade", "remediation"), "retries", "remediateLastFailure") ||
		nestedNumber(release, "spec", "upgrade", "remediation", "retries") != 3 ||
		!exactBool(release, true, "spec", "upgrade", "remediation", "remediateLastFailure") ||
		!exactMappingKeys(nested(release, "spec", "rollback"), "cleanupOnFail") ||
		!exactBool(release, true, "spec", "rollback", "cleanupOnFail") ||
		!exactMappingKeys(nested(release, "spec", "driftDetection"), "mode") ||
		nestedString(release, "spec", "driftDetection", "mode") != "enabled" {
		return errors.New("cert-manager CRD or remediation policy is invalid")
	}

	values, ok := nested(release, "spec", "values").(map[string]any)
	if !ok || !exactMappingKeys(values,
		"global", "crds", "replicaCount", "enableCertificateOwnerRef", "strategy",
		"podDisruptionBudget", "topologySpreadConstraints", "image", "securityContext",
		"containerSecurityContext", "resources", "webhook", "cainjector", "startupapicheck", "acmesolver") {
		return errors.New("cert-manager values inventory is not exact")
	}
	if !exactMappingKeys(nested(values, "global"), "rbac", "leaderElection") ||
		!exactMappingKeys(nested(values, "global", "rbac"), "aggregateClusterRoles") ||
		!exactBool(values, false, "global", "rbac", "aggregateClusterRoles") ||
		!exactMappingKeys(nested(values, "global", "leaderElection"), "namespace") ||
		nestedString(values, "global", "leaderElection", "namespace") != "cert-manager" ||
		!exactMappingKeys(nested(values, "crds"), "enabled", "keep") ||
		!exactBool(values, true, "crds", "enabled") || !exactBool(values, true, "crds", "keep") ||
		!exactBool(values, false, "enableCertificateOwnerRef") {
		return errors.New("cert-manager RBAC, leader election, or CRD values are invalid")
	}
	if err := validateCertManagerHAComponent(values, nil, "controller", "100m", "128Mi", "1", "512Mi"); err != nil {
		return err
	}
	webhook, ok := nested(values, "webhook").(map[string]any)
	if !ok || !exactMappingKeys(webhook, "replicaCount", "timeoutSeconds", "strategy", "podDisruptionBudget", "topologySpreadConstraints", "image", "securityContext", "containerSecurityContext", "resources") ||
		nestedNumber(values, "webhook", "timeoutSeconds") != 10 {
		return errors.New("cert-manager webhook values are invalid")
	}
	if err := validateCertManagerHAComponent(values, []string{"webhook"}, "webhook", "50m", "64Mi", "500m", "256Mi"); err != nil {
		return err
	}
	cainjector, ok := nested(values, "cainjector").(map[string]any)
	if !ok || !exactMappingKeys(cainjector, "enabled", "replicaCount", "strategy", "podDisruptionBudget", "topologySpreadConstraints", "image", "securityContext", "containerSecurityContext", "resources") ||
		!exactBool(values, true, "cainjector", "enabled") {
		return errors.New("cert-manager CA injector values are invalid")
	}
	if err := validateCertManagerHAComponent(values, []string{"cainjector"}, "cainjector", "50m", "64Mi", "500m", "256Mi"); err != nil {
		return err
	}
	if err := validateCertManagerAuxiliaryImages(values); err != nil {
		return err
	}
	return nil
}

func validateCertManagerHAComponent(values map[string]any, prefix []string, component, requestCPU, requestMemory, limitCPU, limitMemory string) error {
	path := func(parts ...string) []string {
		result := make([]string, 0, len(prefix)+len(parts))
		result = append(result, prefix...)
		return append(result, parts...)
	}
	if nestedNumber(values, path("replicaCount")...) != 3 ||
		!exactMappingKeys(nested(values, path("strategy")...), "type", "rollingUpdate") ||
		nestedString(values, path("strategy", "type")...) != "RollingUpdate" ||
		!exactMappingKeys(nested(values, path("strategy", "rollingUpdate")...), "maxSurge", "maxUnavailable") ||
		nestedNumber(values, path("strategy", "rollingUpdate", "maxSurge")...) != 1 ||
		nestedNumber(values, path("strategy", "rollingUpdate", "maxUnavailable")...) != 1 ||
		!exactMappingKeys(nested(values, path("podDisruptionBudget")...), "enabled", "minAvailable") ||
		!exactBool(values, true, path("podDisruptionBudget", "enabled")...) ||
		nestedNumber(values, path("podDisruptionBudget", "minAvailable")...) != 2 {
		return fmt.Errorf("cert-manager %s replicas, rollout, or disruption budget is invalid", component)
	}
	spreads, ok := nested(values, path("topologySpreadConstraints")...).([]any)
	if !ok || len(spreads) != 1 {
		return fmt.Errorf("cert-manager %s topology spread is invalid", component)
	}
	spread, ok := spreads[0].(map[string]any)
	if !ok || !exactMappingKeys(spread, "maxSkew", "topologyKey", "whenUnsatisfiable", "labelSelector") ||
		nestedNumber(spread, "maxSkew") != 1 || nestedString(spread, "topologyKey") != "kubernetes.io/hostname" ||
		nestedString(spread, "whenUnsatisfiable") != "DoNotSchedule" ||
		!exactMappingKeys(nested(spread, "labelSelector"), "matchLabels") ||
		!exactStringMap(nested(spread, "labelSelector", "matchLabels"), map[string]string{
			"app.kubernetes.io/instance":  "cert-manager",
			"app.kubernetes.io/component": component,
		}) {
		return fmt.Errorf("cert-manager %s topology spread is invalid", component)
	}
	if err := validateCertManagerImage(values, path("image"), component); err != nil {
		return err
	}
	if !exactMappingKeys(nested(values, path("securityContext")...), "runAsNonRoot", "seccompProfile") ||
		!exactBool(values, true, path("securityContext", "runAsNonRoot")...) ||
		!exactMappingKeys(nested(values, path("securityContext", "seccompProfile")...), "type") ||
		nestedString(values, path("securityContext", "seccompProfile", "type")...) != "RuntimeDefault" ||
		!exactMappingKeys(nested(values, path("containerSecurityContext")...), "allowPrivilegeEscalation", "readOnlyRootFilesystem", "capabilities") ||
		!exactBool(values, false, path("containerSecurityContext", "allowPrivilegeEscalation")...) ||
		!exactBool(values, true, path("containerSecurityContext", "readOnlyRootFilesystem")...) ||
		!exactMappingKeys(nested(values, path("containerSecurityContext", "capabilities")...), "drop") ||
		!exactStringSequence(nested(values, path("containerSecurityContext", "capabilities", "drop")...), "ALL") {
		return fmt.Errorf("cert-manager %s security context is invalid", component)
	}
	if !exactMappingKeys(nested(values, path("resources")...), "requests", "limits") ||
		!exactMappingKeys(nested(values, path("resources", "requests")...), "cpu", "memory") ||
		!exactMappingKeys(nested(values, path("resources", "limits")...), "cpu", "memory") ||
		nestedString(values, path("resources", "requests", "cpu")...) != requestCPU ||
		nestedString(values, path("resources", "requests", "memory")...) != requestMemory ||
		nestedString(values, path("resources", "limits", "cpu")...) != limitCPU ||
		nestedString(values, path("resources", "limits", "memory")...) != limitMemory {
		return fmt.Errorf("cert-manager %s resources are invalid", component)
	}
	return nil
}

func validateCertManagerAuxiliaryImages(values map[string]any) error {
	startup, ok := nested(values, "startupapicheck").(map[string]any)
	if !ok || !exactMappingKeys(startup, "enabled", "timeout", "backoffLimit", "image", "securityContext", "containerSecurityContext", "resources") ||
		!exactBool(values, true, "startupapicheck", "enabled") ||
		nestedString(values, "startupapicheck", "timeout") != "2m" ||
		nestedNumber(values, "startupapicheck", "backoffLimit") != 6 ||
		!exactMappingKeys(nested(values, "startupapicheck", "securityContext"), "runAsNonRoot", "seccompProfile") ||
		!exactBool(values, true, "startupapicheck", "securityContext", "runAsNonRoot") ||
		!exactMappingKeys(nested(values, "startupapicheck", "securityContext", "seccompProfile"), "type") ||
		nestedString(values, "startupapicheck", "securityContext", "seccompProfile", "type") != "RuntimeDefault" ||
		!exactMappingKeys(nested(values, "startupapicheck", "containerSecurityContext"), "allowPrivilegeEscalation", "readOnlyRootFilesystem", "capabilities") ||
		!exactBool(values, false, "startupapicheck", "containerSecurityContext", "allowPrivilegeEscalation") ||
		!exactBool(values, true, "startupapicheck", "containerSecurityContext", "readOnlyRootFilesystem") ||
		!exactMappingKeys(nested(values, "startupapicheck", "containerSecurityContext", "capabilities"), "drop") ||
		!exactStringSequence(nested(values, "startupapicheck", "containerSecurityContext", "capabilities", "drop"), "ALL") ||
		!exactMappingKeys(nested(values, "startupapicheck", "resources"), "requests", "limits") ||
		!exactMappingKeys(nested(values, "startupapicheck", "resources", "requests"), "cpu", "memory") ||
		!exactMappingKeys(nested(values, "startupapicheck", "resources", "limits"), "cpu", "memory") ||
		nestedString(values, "startupapicheck", "resources", "requests", "cpu") != "10m" ||
		nestedString(values, "startupapicheck", "resources", "requests", "memory") != "32Mi" ||
		nestedString(values, "startupapicheck", "resources", "limits", "cpu") != "100m" ||
		nestedString(values, "startupapicheck", "resources", "limits", "memory") != "128Mi" {
		return errors.New("cert-manager startup API check is invalid")
	}
	if err := validateCertManagerImage(values, []string{"startupapicheck", "image"}, "startupapicheck"); err != nil {
		return err
	}
	if !exactMappingKeys(nested(values, "acmesolver"), "image") {
		return errors.New("cert-manager ACME solver values are invalid")
	}
	return validateCertManagerImage(values, []string{"acmesolver", "image"}, "acmesolver")
}

func validateCertManagerImage(values map[string]any, path []string, component string) error {
	pin, found := certManagerImages[component]
	if !found || !exactMappingKeys(nested(values, path...), "repository", "tag", "digest", "pullPolicy") ||
		nestedString(values, append(path, "repository")...) != pin.repository ||
		nestedString(values, append(path, "tag")...) != certManagerVersion ||
		nestedString(values, append(path, "digest")...) != pin.digest ||
		nestedString(values, append(path, "pullPolicy")...) != "IfNotPresent" {
		return fmt.Errorf("cert-manager %s image pin is invalid", component)
	}
	return nil
}
