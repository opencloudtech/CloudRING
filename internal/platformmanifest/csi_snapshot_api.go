// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package platformmanifest

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

const (
	csiSnapshotAPIProfilePath     = "deploy/kubernetes/storage/csi-snapshot-api"
	csiSnapshotVersion            = "v8.5.0"
	csiSnapshotCommit             = "5aab051d1af135e2c852f6fb7fc27fa709d877bf"
	csiSnapshotControllerImage    = "registry.k8s.io/sig-storage/snapshot-controller:v8.5.0@sha256:74ca61ab13e978f03cf0f336a607281d15f04cda0a38a881306365473b28a3d8"
	csiSnapshotUpstreamRBACSHA256 = "99c4ac480b6c9563be0d85599e29cc7b68b25a82d250b0e789726727551e8d38"
	csiSnapshotUpstreamDeployHash = "bab025e1fed9199c5d827f64febb572dd8b746928e48d656312a215bede74d92"
)

var csiSnapshotCRDs = []struct {
	file       string
	name       string
	kind       string
	plural     string
	scope      string
	sha256     string
	shortNames []string
}{
	{
		file:       "snapshot.storage.k8s.io_volumesnapshotclasses.yaml",
		name:       "volumesnapshotclasses.snapshot.storage.k8s.io",
		kind:       "VolumeSnapshotClass",
		plural:     "volumesnapshotclasses",
		scope:      "Cluster",
		sha256:     "75e6565aac2c0f2949ed13ea884bbaa388cb7be576b558b709cf1168e011828d",
		shortNames: []string{"vsclass", "vsclasses"},
	},
	{
		file:       "snapshot.storage.k8s.io_volumesnapshotcontents.yaml",
		name:       "volumesnapshotcontents.snapshot.storage.k8s.io",
		kind:       "VolumeSnapshotContent",
		plural:     "volumesnapshotcontents",
		scope:      "Cluster",
		sha256:     "895a3c1e73b60f06a0deb566dd123d01bdf1b2efc5d5ff5231ff8bbcf42dafc7",
		shortNames: []string{"vsc", "vscs"},
	},
	{
		file:       "snapshot.storage.k8s.io_volumesnapshots.yaml",
		name:       "volumesnapshots.snapshot.storage.k8s.io",
		kind:       "VolumeSnapshot",
		plural:     "volumesnapshots",
		scope:      "Namespaced",
		sha256:     "b032116e987fb1d7d93cec7d942833adeb9d95c9bdc7e00c10b280c2fe4a6c33",
		shortNames: []string{"vs"},
	},
}

// VerifyCSISnapshotAPI validates the single provider-neutral owner of the CSI
// snapshot CRDs and controller. Structural success is not live snapshot or
// restore evidence.
func VerifyCSISnapshotAPI(root string) (Report, error) {
	root, err := canonicalRoot(root)
	if err != nil {
		return Report{}, err
	}
	report := Report{Status: "blocked", Profile: "cloudring-csi-snapshot-api/v1"}
	repository, err := os.OpenRoot(root)
	if err != nil {
		return report, errors.New("open confined repository root")
	}
	defer repository.Close()

	crdObjects, err := readCSISnapshotCRDs(repository)
	if err != nil {
		return report, err
	}
	controllerObjects, err := readCSISnapshotController(repository)
	if err != nil {
		return report, err
	}
	if err := validateCanonicalCSISnapshotOwnership(repository, filepath.Join("deploy", "kubernetes", "storage")); err != nil {
		return report, err
	}
	readme, err := readRegular(repository, filepath.Join(csiSnapshotAPIProfilePath, "README.md"))
	if err != nil {
		return report, err
	}
	for _, required := range [][]byte{
		[]byte("single provider-neutral owner"),
		[]byte("intentionally not composed into a live GitOps root"),
		[]byte("does not prove"),
		[]byte("CRDs to report `Established=True`"),
		[]byte("make `controller` depend on the Ready CRD Kustomization"),
		[]byte("make the selected Longhorn or Rook-Ceph profile Kustomization depend on the Ready controller Kustomization"),
		[]byte(csiSnapshotCommit),
		[]byte(csiSnapshotControllerImage[strings.Index(csiSnapshotControllerImage, "sha256:"):]),
	} {
		if !bytes.Contains(readme, required) {
			return report, errors.New("CSI snapshot API ownership, ordering, provenance, or non-claim documentation is incomplete")
		}
	}

	report.Files = 7
	report.Documents = len(crdObjects) + len(controllerObjects)
	if report.Documents != 10 {
		return report, errors.New("CSI snapshot API source inventory is incomplete")
	}
	if err := validateCSISnapshotCRDObjects(crdObjects); err != nil {
		return report, err
	}
	if err := validateCSISnapshotControllerObjects(controllerObjects); err != nil {
		return report, err
	}
	report.Status = "ready"
	report.Checks = []string{
		"three_v1_crds_byte_pinned_to_upstream_release",
		"upstream_tag_commit_and_asset_checksums_recorded",
		"single_provider_neutral_controller_owner",
		"controller_image_digest_pinned",
		"controller_two_replicas_and_leader_election_ready",
		"hard_host_topology_spread_ready",
		"controller_disruption_budget_ready",
		"least_privilege_volume_snapshot_rbac_only",
		"flux_crd_controller_profile_order_documented",
		"live_snapshot_restore_and_one_node_loss_non_claim_preserved",
	}
	return report, nil
}

func validateCanonicalCSISnapshotOwnership(root *os.Root, directory string) error {
	handle, err := root.Open(directory)
	if err != nil {
		return errors.New("read CSI snapshot ownership scope")
	}
	defer handle.Close()
	entries, err := handle.ReadDir(-1)
	if err != nil {
		return errors.New("read CSI snapshot ownership scope")
	}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("CSI snapshot ownership scope contains a symbolic link")
		}
		if entry.IsDir() {
			// Vendored Helm templates are immutable chart inputs, not a second
			// applied manifest owner. The Longhorn verifier independently checks
			// their exact upstream archive and complete tree digests.
			if filepath.Clean(path) == filepath.Clean(longhornVendoredRoot) {
				continue
			}
			if err := validateCanonicalCSISnapshotOwnership(root, path); err != nil {
				return err
			}
			continue
		}
		extension := filepath.Ext(path)
		if (extension != ".yaml" && extension != ".yml") || entry.Name() == "kustomization.yaml" || entry.Name() == "kustomization.yml" {
			continue
		}
		data, err := readRegular(root, path)
		if err != nil {
			return err
		}
		objects, err := decodeObjects(data)
		if err != nil {
			return fmt.Errorf("decode CSI snapshot ownership candidate %s: %w", path, err)
		}
		for _, item := range objects {
			if item.Kind == "Deployment" && path != filepath.Join(csiSnapshotAPIProfilePath, "controller", "resources.yaml") &&
				(item.Name == "snapshot-controller" || deploymentUsesSnapshotControllerImage(item.Data)) {
				return errors.New("snapshot-controller has more than one manifest owner")
			}
			if item.Kind != "CustomResourceDefinition" || !isCSISnapshotCRDName(item.Name) {
				continue
			}
			expected := filepath.Join(csiSnapshotAPIProfilePath, "crds")
			if filepath.Dir(path) != expected {
				return errors.New("CSI snapshot CRD has more than one manifest owner")
			}
		}
	}
	return nil
}

func deploymentUsesSnapshotControllerImage(deployment map[string]any) bool {
	containers, ok := nested(deployment, "spec", "template", "spec", "containers").([]any)
	if !ok {
		return false
	}
	for _, raw := range containers {
		container, ok := raw.(map[string]any)
		if ok && strings.Contains(stringValue(container["image"]), "sig-storage/snapshot-controller") {
			return true
		}
	}
	return false
}

func isCSISnapshotCRDName(name string) bool {
	for _, crd := range csiSnapshotCRDs {
		if crd.name == name {
			return true
		}
	}
	return false
}

func readCSISnapshotCRDs(root *os.Root) ([]object, error) {
	directory := filepath.Join(csiSnapshotAPIProfilePath, "crds")
	resources := make([]string, 0, len(csiSnapshotCRDs))
	for _, crd := range csiSnapshotCRDs {
		resources = append(resources, crd.file)
	}
	if err := validateSimpleKustomization(root, filepath.Join(directory, "kustomization.yaml"), resources...); err != nil {
		return nil, fmt.Errorf("CSI snapshot CRD stage: %w", err)
	}
	objects := make([]object, 0, len(csiSnapshotCRDs))
	for _, crd := range csiSnapshotCRDs {
		data, err := readRegular(root, filepath.Join(directory, crd.file))
		if err != nil {
			return nil, err
		}
		normalized := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
		if bytes.Contains(normalized, []byte("\r")) || fmt.Sprintf("%x", sha256.Sum256(normalized)) != crd.sha256 {
			return nil, fmt.Errorf("CSI snapshot CRD %s differs from the pinned upstream v8.5.0 asset", crd.name)
		}
		decoded, err := decodeObjects(data)
		if err != nil || len(decoded) != 1 {
			return nil, fmt.Errorf("decode CSI snapshot CRD %s", crd.name)
		}
		objects = append(objects, decoded[0])
	}
	return objects, nil
}

func validateCSISnapshotCRDObjects(objects []object) error {
	if len(objects) != len(csiSnapshotCRDs) {
		return errors.New("CSI snapshot CRD inventory is not exact")
	}
	for index, item := range objects {
		expected := csiSnapshotCRDs[index]
		if item.Kind != "CustomResourceDefinition" || item.Name != expected.name || item.Namespace != "" ||
			nestedString(item.Data, "apiVersion") != "apiextensions.k8s.io/v1" ||
			nestedString(item.Data, "spec", "group") != "snapshot.storage.k8s.io" ||
			nestedString(item.Data, "spec", "scope") != expected.scope ||
			nestedString(item.Data, "spec", "names", "kind") != expected.kind ||
			nestedString(item.Data, "spec", "names", "plural") != expected.plural ||
			!exactStringSequence(nested(item.Data, "spec", "names", "shortNames"), expected.shortNames...) {
			return fmt.Errorf("CSI snapshot CRD %s identity or scope is invalid", expected.name)
		}
		versions, ok := nested(item.Data, "spec", "versions").([]any)
		if !ok || len(versions) != 2 {
			return fmt.Errorf("CSI snapshot CRD %s version inventory is invalid", expected.name)
		}
		stable, stableOK := versions[0].(map[string]any)
		legacy, legacyOK := versions[1].(map[string]any)
		if !stableOK || stringValue(stable["name"]) != "v1" || !exactBool(stable, true, "served") || !exactBool(stable, true, "storage") || nested(stable, "schema", "openAPIV3Schema") == nil ||
			!legacyOK || stringValue(legacy["name"]) != "v1beta1" || !exactBool(legacy, false, "served") || !exactBool(legacy, false, "storage") || nested(legacy, "schema", "openAPIV3Schema") == nil {
			return fmt.Errorf("CSI snapshot CRD %s v1 schema is invalid", expected.name)
		}
	}
	return nil
}

func readCSISnapshotController(root *os.Root) ([]object, error) {
	directory := filepath.Join(csiSnapshotAPIProfilePath, "controller")
	if err := validateSimpleKustomization(root, filepath.Join(directory, "kustomization.yaml"), "resources.yaml"); err != nil {
		return nil, fmt.Errorf("CSI snapshot controller stage: %w", err)
	}
	data, err := readRegular(root, filepath.Join(directory, "resources.yaml"))
	if err != nil {
		return nil, err
	}
	for _, forbidden := range [][]byte{
		[]byte(":latest"), []byte("REPLACE_WITH"), []byte("example.invalid"),
		[]byte("kind: Secret"), []byte("groupsnapshot.storage.k8s.io"),
		[]byte("resources: [\"*\"]"), []byte("verbs: [\"*\"]"),
	} {
		if bytes.Contains(data, forbidden) {
			return nil, errors.New("CSI snapshot controller contains mutable, unresolved, secret, group-snapshot, or wildcard access")
		}
	}
	objects, err := decodeObjects(data)
	if err != nil {
		return nil, fmt.Errorf("decode CSI snapshot controller: %w", err)
	}
	return objects, nil
}

func validateCSISnapshotControllerObjects(objects []object) error {
	index := make(map[string]object, len(objects))
	for _, item := range objects {
		key := item.Kind + "/" + item.Namespace + "/" + item.Name
		if _, duplicate := index[key]; duplicate {
			return errors.New("duplicate CSI snapshot controller object identity")
		}
		index[key] = item
	}
	expected := []string{
		"ClusterRole//cloudring-snapshot-controller",
		"ClusterRoleBinding//cloudring-snapshot-controller",
		"Deployment/kube-system/snapshot-controller",
		"PodDisruptionBudget/kube-system/snapshot-controller",
		"Role/kube-system/cloudring-snapshot-controller-leader-election",
		"RoleBinding/kube-system/cloudring-snapshot-controller-leader-election",
		"ServiceAccount/kube-system/snapshot-controller",
	}
	actual := make([]string, 0, len(index))
	for key := range index {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		return errors.New("CSI snapshot controller object inventory is not exact")
	}
	if err := validateCSISnapshotRBAC(index); err != nil {
		return err
	}
	if err := validateCSISnapshotDeployment(index["Deployment/kube-system/snapshot-controller"].Data); err != nil {
		return err
	}
	budget := index["PodDisruptionBudget/kube-system/snapshot-controller"].Data
	if nestedString(budget, "apiVersion") != "policy/v1" ||
		nestedNumber(budget, "spec", "minAvailable") != 1 ||
		!exactStringMap(nested(budget, "spec", "selector", "matchLabels"), map[string]string{"app.kubernetes.io/name": "snapshot-controller"}) {
		return errors.New("CSI snapshot controller disruption budget is invalid")
	}
	return nil
}

func validateCSISnapshotRBAC(index map[string]object) error {
	labels := csiSnapshotControllerLabels()
	serviceAccount := index["ServiceAccount/kube-system/snapshot-controller"].Data
	if !exactMappingKeys(serviceAccount, "apiVersion", "kind", "metadata") || nestedString(serviceAccount, "apiVersion") != "v1" ||
		!exactStringMap(nested(serviceAccount, "metadata", "labels"), labels) {
		return errors.New("CSI snapshot controller service account is invalid")
	}
	clusterRole := index["ClusterRole//cloudring-snapshot-controller"].Data
	expectedRules := []any{
		map[string]any{"apiGroups": []any{""}, "resources": []any{"persistentvolumes"}, "verbs": []any{"get", "list", "watch"}},
		map[string]any{"apiGroups": []any{""}, "resources": []any{"persistentvolumeclaims"}, "verbs": []any{"get", "list", "watch", "update"}},
		map[string]any{"apiGroups": []any{""}, "resources": []any{"events"}, "verbs": []any{"list", "watch", "create", "update", "patch"}},
		map[string]any{"apiGroups": []any{"snapshot.storage.k8s.io"}, "resources": []any{"volumesnapshotclasses"}, "verbs": []any{"get", "list", "watch"}},
		map[string]any{"apiGroups": []any{"snapshot.storage.k8s.io"}, "resources": []any{"volumesnapshotcontents"}, "verbs": []any{"create", "get", "list", "watch", "update", "delete", "patch"}},
		map[string]any{"apiGroups": []any{"snapshot.storage.k8s.io"}, "resources": []any{"volumesnapshotcontents/status"}, "verbs": []any{"patch"}},
		map[string]any{"apiGroups": []any{"snapshot.storage.k8s.io"}, "resources": []any{"volumesnapshots"}, "verbs": []any{"create", "get", "list", "watch", "update", "patch", "delete"}},
		map[string]any{"apiGroups": []any{"snapshot.storage.k8s.io"}, "resources": []any{"volumesnapshots/status"}, "verbs": []any{"update", "patch"}},
	}
	if !exactMappingKeys(clusterRole, "apiVersion", "kind", "metadata", "rules") ||
		nestedString(clusterRole, "apiVersion") != "rbac.authorization.k8s.io/v1" ||
		!exactMappingKeys(nested(clusterRole, "metadata"), "name", "labels", "annotations") ||
		!exactStringMap(nested(clusterRole, "metadata", "labels"), labels) ||
		!exactStringMap(nested(clusterRole, "metadata", "annotations"), map[string]string{
			"cloudring.org/upstream-source":          "kubernetes-csi/external-snapshotter@" + csiSnapshotVersion,
			"cloudring.org/upstream-commit":          csiSnapshotCommit,
			"cloudring.org/upstream-baseline-sha256": csiSnapshotUpstreamRBACSHA256,
		}) || !reflect.DeepEqual(nested(clusterRole, "rules"), expectedRules) {
		return errors.New("CSI snapshot controller cluster RBAC is invalid")
	}
	if !validateCSISnapshotBinding(index["ClusterRoleBinding//cloudring-snapshot-controller"].Data, "ClusterRole", "cloudring-snapshot-controller", labels) {
		return errors.New("CSI snapshot controller cluster role binding is invalid")
	}
	leaderRole := index["Role/kube-system/cloudring-snapshot-controller-leader-election"].Data
	expectedLeaderRules := []any{map[string]any{
		"apiGroups": []any{"coordination.k8s.io"},
		"resources": []any{"leases"},
		"verbs":     []any{"get", "watch", "list", "delete", "update", "create"},
	}}
	if !exactMappingKeys(leaderRole, "apiVersion", "kind", "metadata", "rules") ||
		nestedString(leaderRole, "apiVersion") != "rbac.authorization.k8s.io/v1" ||
		!exactMappingKeys(nested(leaderRole, "metadata"), "name", "namespace", "labels") ||
		!exactStringMap(nested(leaderRole, "metadata", "labels"), labels) ||
		!reflect.DeepEqual(nested(leaderRole, "rules"), expectedLeaderRules) {
		return errors.New("CSI snapshot controller leader-election RBAC is invalid")
	}
	if !validateCSISnapshotBinding(index["RoleBinding/kube-system/cloudring-snapshot-controller-leader-election"].Data, "Role", "cloudring-snapshot-controller-leader-election", labels) {
		return errors.New("CSI snapshot controller leader-election role binding is invalid")
	}
	return nil
}

func validateCSISnapshotBinding(binding map[string]any, roleKind, roleName string, labels map[string]string) bool {
	if !exactMappingKeys(binding, "apiVersion", "kind", "metadata", "subjects", "roleRef") ||
		nestedString(binding, "apiVersion") != "rbac.authorization.k8s.io/v1" ||
		!exactStringMap(nested(binding, "metadata", "labels"), labels) {
		return false
	}
	roleRef, ok := nested(binding, "roleRef").(map[string]any)
	if !ok || !exactMappingKeys(roleRef, "apiGroup", "kind", "name") || stringValue(roleRef["apiGroup"]) != "rbac.authorization.k8s.io" ||
		stringValue(roleRef["kind"]) != roleKind || stringValue(roleRef["name"]) != roleName {
		return false
	}
	subjects, ok := nested(binding, "subjects").([]any)
	if !ok || len(subjects) != 1 {
		return false
	}
	subject, ok := subjects[0].(map[string]any)
	return ok && exactMappingKeys(subject, "kind", "name", "namespace") &&
		stringValue(subject["kind"]) == "ServiceAccount" && stringValue(subject["name"]) == "snapshot-controller" && stringValue(subject["namespace"]) == "kube-system"
}

func validateCSISnapshotDeployment(deployment map[string]any) error {
	labels := csiSnapshotControllerLabels()
	if !exactMappingKeys(deployment, "apiVersion", "kind", "metadata", "spec") || nestedString(deployment, "apiVersion") != "apps/v1" ||
		!exactStringMap(nested(deployment, "metadata", "labels"), labels) ||
		!exactStringMap(nested(deployment, "metadata", "annotations"), map[string]string{
			"cloudring.org/upstream-source":          "kubernetes-csi/external-snapshotter@" + csiSnapshotVersion,
			"cloudring.org/upstream-commit":          csiSnapshotCommit,
			"cloudring.org/upstream-baseline-sha256": csiSnapshotUpstreamDeployHash,
			"cloudring.org/non-claim":                "downstream-crd-controller-snapshot-restore-and-one-node-loss-evidence-required",
			"cloudring.org/requires-stage":           "deploy/kubernetes/storage/csi-snapshot-api/crds",
		}) || nestedNumber(deployment, "spec", "replicas") != 2 || nestedNumber(deployment, "spec", "minReadySeconds") != 35 ||
		nestedString(deployment, "spec", "strategy", "type") != "RollingUpdate" || nestedNumber(deployment, "spec", "strategy", "rollingUpdate", "maxSurge") != 1 ||
		nestedNumber(deployment, "spec", "strategy", "rollingUpdate", "maxUnavailable") != 0 ||
		!exactStringMap(nested(deployment, "spec", "selector", "matchLabels"), map[string]string{"app.kubernetes.io/name": "snapshot-controller"}) ||
		!exactStringMap(nested(deployment, "spec", "template", "metadata", "labels"), labels) {
		return errors.New("CSI snapshot controller deployment identity, provenance, replicas, or rollout is invalid")
	}
	podSpec, ok := nested(deployment, "spec", "template", "spec").(map[string]any)
	if !ok || !exactMappingKeys(podSpec, "serviceAccountName", "priorityClassName", "nodeSelector", "tolerations", "topologySpreadConstraints", "securityContext", "containers") ||
		nestedString(podSpec, "serviceAccountName") != "snapshot-controller" || nestedString(podSpec, "priorityClassName") != "system-cluster-critical" ||
		nestedString(podSpec, "nodeSelector", "kubernetes.io/os") != "linux" || !exactBool(podSpec, true, "securityContext", "runAsNonRoot") ||
		nestedString(podSpec, "securityContext", "seccompProfile", "type") != "RuntimeDefault" || !validateCSISnapshotToleration(podSpec) || !validateCSISnapshotTopology(podSpec) {
		return errors.New("CSI snapshot controller pod security, topology, or scheduling is invalid")
	}
	containers, ok := podSpec["containers"].([]any)
	if !ok || len(containers) != 1 {
		return errors.New("CSI snapshot controller container inventory is invalid")
	}
	container, ok := containers[0].(map[string]any)
	if !ok || !exactMappingKeys(container, "name", "image", "imagePullPolicy", "args", "ports", "livenessProbe", "readinessProbe", "securityContext", "resources") ||
		stringValue(container["name"]) != "snapshot-controller" || stringValue(container["image"]) != csiSnapshotControllerImage ||
		stringValue(container["imagePullPolicy"]) != "IfNotPresent" || !exactStringSequence(container["args"], "--v=2", "--leader-election=true", "--http-endpoint=:8080") ||
		!validateCSISnapshotPort(container) ||
		!validateCSISnapshotProbe(container, "livenessProbe", 15) || !validateCSISnapshotProbe(container, "readinessProbe", 5) ||
		!exactBool(container, false, "securityContext", "allowPrivilegeEscalation") || !exactBool(container, true, "securityContext", "readOnlyRootFilesystem") ||
		!exactBool(container, true, "securityContext", "runAsNonRoot") || nestedNumber(container, "securityContext", "runAsUser") != 65532 ||
		nestedNumber(container, "securityContext", "runAsGroup") != 65532 || !exactStringSequence(nested(container, "securityContext", "capabilities", "drop"), "ALL") ||
		nestedString(container, "resources", "requests", "cpu") != "10m" || nestedString(container, "resources", "requests", "memory") != "32Mi" ||
		nestedString(container, "resources", "limits", "cpu") != "250m" || nestedString(container, "resources", "limits", "memory") != "128Mi" {
		return errors.New("CSI snapshot controller image, leader election, health, security, or resources are invalid")
	}
	return nil
}

func validateCSISnapshotPort(container map[string]any) bool {
	ports, ok := container["ports"].([]any)
	if !ok || len(ports) != 1 {
		return false
	}
	port, ok := ports[0].(map[string]any)
	return ok && exactMappingKeys(port, "name", "containerPort", "protocol") && stringValue(port["name"]) == "health" &&
		nestedNumber(port, "containerPort") == 8080 && stringValue(port["protocol"]) == "TCP"
}

func validateCSISnapshotToleration(podSpec map[string]any) bool {
	items, ok := podSpec["tolerations"].([]any)
	if !ok || len(items) != 1 {
		return false
	}
	item, ok := items[0].(map[string]any)
	return ok && exactMappingKeys(item, "key", "operator", "effect") && stringValue(item["key"]) == "node-role.kubernetes.io/control-plane" &&
		stringValue(item["operator"]) == "Exists" && stringValue(item["effect"]) == "NoSchedule"
}

func validateCSISnapshotTopology(podSpec map[string]any) bool {
	items, ok := podSpec["topologySpreadConstraints"].([]any)
	if !ok || len(items) != 1 {
		return false
	}
	item, ok := items[0].(map[string]any)
	return ok && exactMappingKeys(item, "maxSkew", "minDomains", "topologyKey", "whenUnsatisfiable", "labelSelector") && nestedNumber(item, "maxSkew") == 1 && nestedNumber(item, "minDomains") == 2 &&
		nestedString(item, "topologyKey") == "kubernetes.io/hostname" && nestedString(item, "whenUnsatisfiable") == "DoNotSchedule" &&
		exactStringMap(nested(item, "labelSelector", "matchLabels"), map[string]string{"app.kubernetes.io/name": "snapshot-controller"})
}

func validateCSISnapshotProbe(container map[string]any, name string, initialDelay int) bool {
	probe, ok := container[name].(map[string]any)
	return ok && exactMappingKeys(probe, "httpGet", "initialDelaySeconds", "periodSeconds", "timeoutSeconds", "failureThreshold") &&
		exactMappingKeys(nested(probe, "httpGet"), "path", "port") &&
		nestedString(probe, "httpGet", "path") == "/healthz/leader-election" && nestedString(probe, "httpGet", "port") == "health" &&
		nestedNumber(probe, "initialDelaySeconds") == initialDelay && nestedNumber(probe, "periodSeconds") == 10 && nestedNumber(probe, "timeoutSeconds") == 5 && nestedNumber(probe, "failureThreshold") == 3
}

func csiSnapshotControllerLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "snapshot-controller",
		"app.kubernetes.io/component": "csi-snapshot-control-plane",
		"app.kubernetes.io/part-of":   "cloudring-storage",
	}
}
