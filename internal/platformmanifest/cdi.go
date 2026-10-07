// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package platformmanifest

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	cdiProfilePath      = "deploy/kubernetes/virtualization/cdi"
	cdiOperatorManifest = "upstream-cdi-operator-v1.65.0.yaml"
	cdiOperatorSHA256   = "9fbf6b03ec159c3c69939ebf52d713b984a5fd99be6809eae07c1173b0b41546"
	cdiActivationPatch  = "- op: replace\n  path: /spec/replicas\n  value: 1"
	cdiRuntimeNonClaim  = "downstream-live-import-persistence-backup-and-restore-evidence-required"
)

var cdiOperandImages = map[string]string{
	"CONTROLLER_IMAGE":      "quay.io/kubevirt/cdi-controller:v1.65.0@sha256:c924d99bf27fe6a198f9796c4250d4fb04af3dfc4e850f2a2f089fc4f988c5bf",
	"IMPORTER_IMAGE":        "quay.io/kubevirt/cdi-importer:v1.65.0@sha256:27fad4a3677e15fb6ff61d7ef0ae99c31d0462cc993b4b4f1e3d8988e4d0e698",
	"CLONER_IMAGE":          "quay.io/kubevirt/cdi-cloner:v1.65.0@sha256:4c485d088db067a81fce46899a5a577529c1a97a164f27d666d6317da0a32319",
	"OVIRT_POPULATOR_IMAGE": "quay.io/kubevirt/cdi-importer:v1.65.0@sha256:27fad4a3677e15fb6ff61d7ef0ae99c31d0462cc993b4b4f1e3d8988e4d0e698",
	"APISERVER_IMAGE":       "quay.io/kubevirt/cdi-apiserver:v1.65.0@sha256:bf8bbaf76410bc20adff6c9bd76493fdcf622b0bc0be3aea166eec57b1b34a59",
	"UPLOAD_SERVER_IMAGE":   "quay.io/kubevirt/cdi-uploadserver:v1.65.0@sha256:6d7e71acf3087f4c2de2fa96ed968aff5793f6ba24d3bdb30080912e55929a78",
	"UPLOAD_PROXY_IMAGE":    "quay.io/kubevirt/cdi-uploadproxy:v1.65.0@sha256:6fd47bf9fe695e3299764b7fd7729c5d438558e439c06ada3c472705e9c9d77c",
}

// VerifyCDI validates the provider-neutral CDI source contract without turning
// a structural check into a live import or durability claim.
func VerifyCDI(root string) (Report, error) {
	root, err := canonicalRoot(root)
	if err != nil {
		return Report{}, err
	}
	report := Report{Status: "blocked", Profile: "cloudring-cdi/v1"}
	repository, err := os.OpenRoot(root)
	if err != nil {
		return report, errors.New("open confined repository root")
	}
	defer repository.Close()

	controllers, err := readCDIControllers(repository)
	if err != nil {
		return report, err
	}
	if err := validateCDIActivation(repository); err != nil {
		return report, err
	}
	if err := validateCDIHostPrerequisite(repository); err != nil {
		return report, err
	}
	runtime, err := readCDIRuntime(repository)
	if err != nil {
		return report, err
	}
	report.Files = 6
	report.Documents = len(controllers) + len(runtime)
	if report.Documents != 9 {
		return report, errors.New("CDI source inventory is incomplete")
	}
	if err := validateCDIControllers(controllers); err != nil {
		return report, err
	}
	if err := validateCDIRuntime(runtime); err != nil {
		return report, err
	}
	report.Status = "ready"
	report.Checks = []string{
		"upstream_release_asset_provenance_locked",
		"base_operator_suspended",
		"explicit_activation_overlay_ready",
		"operator_and_operand_images_digest_pinned",
		"delayed_binding_and_webhook_rendering_enabled",
		"workload_safe_uninstall_policy_enabled",
		"non_root_raw_block_device_ownership_required",
		"live_import_persistence_and_restore_non_claim_preserved",
	}
	return report, nil
}

func validateCDIHostPrerequisite(root *os.Root) error {
	data, err := readRegular(root, filepath.Join(cdiProfilePath, "README.md"))
	if err != nil {
		return err
	}
	for _, required := range [][]byte{
		[]byte("device_ownership_from_security_context = true"),
		[]byte("containerd config dump"),
		[]byte("restart containerd one node at a time"),
		[]byte("changing the importer to run as root is not an acceptable substitute"),
	} {
		if !bytes.Contains(data, required) {
			return errors.New("CDI host runtime prerequisite is incomplete")
		}
	}
	return nil
}

func readCDIControllers(root *os.Root) ([]object, error) {
	directory := filepath.Join(cdiProfilePath, "controllers")
	if err := validateSimpleKustomization(root, filepath.Join(directory, "kustomization.yaml"), cdiOperatorManifest); err != nil {
		return nil, fmt.Errorf("CDI controllers stage: %w", err)
	}
	data, err := readRegular(root, filepath.Join(directory, cdiOperatorManifest))
	if err != nil {
		return nil, err
	}
	checksumInput := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if bytes.Contains(checksumInput, []byte("\r")) || fmt.Sprintf("%x", sha256.Sum256(checksumInput)) != cdiOperatorSHA256 {
		return nil, errors.New("CDI vendored operator differs from the reviewed release asset patch")
	}
	for _, forbidden := range [][]byte{[]byte(":latest"), []byte("REPLACE_WITH"), []byte("example.invalid")} {
		if bytes.Contains(data, forbidden) {
			return nil, errors.New("CDI operator contains a mutable or unresolved reference")
		}
	}
	objects, err := decodeObjects(data)
	if err != nil {
		return nil, fmt.Errorf("decode CDI operator: %w", err)
	}
	return objects, nil
}

func validateSimpleKustomization(root *os.Root, path string, resources ...string) error {
	data, err := readRegular(root, path)
	if err != nil {
		return err
	}
	var manifest map[string]any
	if err := decodeOne(data, &manifest); err != nil ||
		!exactMappingKeys(manifest, "apiVersion", "kind", "resources") ||
		nestedString(manifest, "apiVersion") != "kustomize.config.k8s.io/v1beta1" ||
		nestedString(manifest, "kind") != "Kustomization" ||
		!exactStringSequence(manifest["resources"], resources...) {
		return errors.New("invalid kustomization")
	}
	return nil
}

func validateCDIActivation(root *os.Root) error {
	path := filepath.Join(cdiProfilePath, "activation", "kustomization.yaml")
	data, err := readRegular(root, path)
	if err != nil {
		return err
	}
	var manifest map[string]any
	if err := decodeOne(data, &manifest); err != nil ||
		!exactMappingKeys(manifest, "apiVersion", "kind", "resources", "patches") ||
		nestedString(manifest, "apiVersion") != "kustomize.config.k8s.io/v1beta1" ||
		nestedString(manifest, "kind") != "Kustomization" ||
		!exactStringSequence(manifest["resources"], "../controllers") {
		return errors.New("CDI activation stage has an invalid kustomization")
	}
	patches, ok := manifest["patches"].([]any)
	if !ok || len(patches) != 1 {
		return errors.New("CDI activation must contain exactly one operator patch")
	}
	patch, ok := patches[0].(map[string]any)
	if !ok || !exactMappingKeys(patch, "target", "patch") || stringValue(patch["patch"]) != cdiActivationPatch {
		return errors.New("CDI activation operator patch is invalid")
	}
	target, ok := patch["target"].(map[string]any)
	if !ok || !exactMappingKeys(target, "group", "version", "kind", "name", "namespace") ||
		stringValue(target["group"]) != "apps" || stringValue(target["version"]) != "v1" ||
		stringValue(target["kind"]) != "Deployment" || stringValue(target["name"]) != "cdi-operator" ||
		stringValue(target["namespace"]) != "cdi" {
		return errors.New("CDI activation target is invalid")
	}
	return nil
}

func readCDIRuntime(root *os.Root) ([]object, error) {
	directory := filepath.Join(cdiProfilePath, "runtime")
	if err := validateSimpleKustomization(root, filepath.Join(directory, "kustomization.yaml"), "resources.yaml"); err != nil {
		return nil, fmt.Errorf("CDI runtime stage: %w", err)
	}
	data, err := readRegular(root, filepath.Join(directory, "resources.yaml"))
	if err != nil {
		return nil, err
	}
	for _, forbidden := range [][]byte{[]byte(":latest"), []byte("REPLACE_WITH"), []byte("example.invalid"), []byte("kind: Secret")} {
		if bytes.Contains(data, forbidden) {
			return nil, errors.New("CDI runtime contains mutable, unresolved, or secret material")
		}
	}
	objects, err := decodeObjects(data)
	if err != nil {
		return nil, fmt.Errorf("decode CDI runtime: %w", err)
	}
	return objects, nil
}

func validateCDIControllers(objects []object) error {
	index := make(map[string]object, len(objects))
	for _, item := range objects {
		key := item.Kind + "/" + item.Namespace + "/" + item.Name
		if _, duplicate := index[key]; duplicate {
			return errors.New("duplicate CDI controller object identity")
		}
		index[key] = item
	}
	expected := []string{
		"ClusterRole//cdi-operator-cluster",
		"ClusterRoleBinding//cdi-operator",
		"CustomResourceDefinition//cdis.cdi.kubevirt.io",
		"Deployment/cdi/cdi-operator",
		"Namespace//cdi",
		"Role/cdi/cdi-operator",
		"RoleBinding/cdi/cdi-operator",
		"ServiceAccount/cdi/cdi-operator",
	}
	actual := make([]string, 0, len(index))
	for key := range index {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		return errors.New("CDI controller object inventory is not exact")
	}
	crd := index["CustomResourceDefinition//cdis.cdi.kubevirt.io"].Data
	if nestedString(crd, "spec", "group") != "cdi.kubevirt.io" || nestedString(crd, "spec", "scope") != "Cluster" || !cdiV1Beta1Stored(crd) {
		return errors.New("CDI custom resource definition is invalid")
	}
	return validateCDIOperator(index["Deployment/cdi/cdi-operator"].Data)
}

func cdiV1Beta1Stored(crd map[string]any) bool {
	versions, ok := nested(crd, "spec", "versions").([]any)
	if !ok {
		return false
	}
	for _, value := range versions {
		version, ok := value.(map[string]any)
		if ok && nestedString(version, "name") == "v1beta1" && exactBool(version, true, "served") && exactBool(version, true, "storage") {
			return true
		}
	}
	return false
}

func validateCDIOperator(deployment map[string]any) error {
	if nestedNumber(deployment, "spec", "replicas") != 0 ||
		nestedString(deployment, "spec", "template", "spec", "nodeSelector", "kubernetes.io/os") != "linux" ||
		nestedString(deployment, "spec", "template", "spec", "serviceAccountName") != "cdi-operator" ||
		!exactBool(deployment, true, "spec", "template", "spec", "securityContext", "runAsNonRoot") {
		return errors.New("CDI base operator is not safely suspended")
	}
	containers, ok := nested(deployment, "spec", "template", "spec", "containers").([]any)
	if !ok || len(containers) != 1 {
		return errors.New("CDI operator container inventory is invalid")
	}
	container, ok := containers[0].(map[string]any)
	if !ok || stringValue(container["name"]) != "cdi-operator" ||
		stringValue(container["image"]) != "quay.io/kubevirt/cdi-operator:v1.65.0@sha256:42ce149c020523b466cd8cb5e413bad9800d93f502d82ced69a2d98a01944ce5" ||
		stringValue(container["imagePullPolicy"]) != "IfNotPresent" ||
		!exactBool(container, false, "securityContext", "allowPrivilegeEscalation") ||
		!exactBool(container, true, "securityContext", "runAsNonRoot") ||
		!exactStringSequence(nested(container, "securityContext", "capabilities", "drop"), "ALL") {
		return errors.New("CDI operator image or security boundary is invalid")
	}
	return validateCDIOperatorEnvironment(container)
}

func validateCDIOperatorEnvironment(container map[string]any) error {
	environment, ok := container["env"].([]any)
	if !ok || len(environment) != 12 {
		return errors.New("CDI operator environment inventory is invalid")
	}
	expected := map[string]string{
		"DEPLOY_CLUSTER_RESOURCES": "true",
		"OPERATOR_VERSION":         "v1.65.0",
		"VERBOSITY":                "1",
		"PULL_POLICY":              "IfNotPresent",
		"MONITORING_NAMESPACE":     "",
	}
	for name, image := range cdiOperandImages {
		expected[name] = image
	}
	seen := make(map[string]bool, len(environment))
	for _, value := range environment {
		entry, ok := value.(map[string]any)
		if !ok {
			return errors.New("CDI operator environment entry is invalid")
		}
		name := stringValue(entry["name"])
		want, exists := expected[name]
		if !exists || seen[name] || stringValue(entry["value"]) != want || entry["valueFrom"] != nil {
			return errors.New("CDI operator image or configuration is not pinned")
		}
		if name == "MONITORING_NAMESPACE" {
			if !exactMappingKeys(entry, "name") {
				return errors.New("CDI monitoring namespace boundary is invalid")
			}
		} else if !exactMappingKeys(entry, "name", "value") {
			return errors.New("CDI operator environment shape is invalid")
		}
		seen[name] = true
	}
	return nil
}

func validateCDIRuntime(objects []object) error {
	if len(objects) != 1 || objects[0].Kind != "CDI" || objects[0].Name != "cdi" || objects[0].Namespace != "" {
		return errors.New("CDI runtime object inventory is not exact")
	}
	resource := objects[0].Data
	if !exactMappingKeys(resource, "apiVersion", "kind", "metadata", "spec") ||
		nestedString(resource, "apiVersion") != "cdi.kubevirt.io/v1beta1" ||
		nestedString(resource, "metadata", "annotations", "cloudring.org/non-claim") != cdiRuntimeNonClaim ||
		nestedString(resource, "spec", "uninstallStrategy") != "BlockUninstallIfWorkloadsExist" ||
		nestedString(resource, "spec", "imagePullPolicy") != "IfNotPresent" ||
		!exactStringSequence(nested(resource, "spec", "config", "featureGates"), "HonorWaitForFirstConsumer", "WebhookPvcRendering") ||
		nestedString(resource, "spec", "infra", "nodeSelector", "kubernetes.io/os") != "linux" ||
		nestedString(resource, "spec", "workload", "nodeSelector", "kubernetes.io/os") != "linux" {
		return errors.New("CDI runtime safety boundary is invalid")
	}
	if !exactMappingKeys(nested(resource, "spec"), "uninstallStrategy", "config", "imagePullPolicy", "infra", "workload") ||
		!exactMappingKeys(nested(resource, "spec", "config"), "featureGates") ||
		!exactMappingKeys(nested(resource, "spec", "infra"), "nodeSelector") ||
		!exactMappingKeys(nested(resource, "spec", "workload"), "nodeSelector") {
		return errors.New("CDI runtime contains an unreviewed option")
	}
	return nil
}
