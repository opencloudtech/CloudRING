// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

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

const rookCephRBDProfilePath = "deploy/kubernetes/storage/rook-ceph-rbd"

// VerifyRookCephRBD validates the reusable source profile without contacting a
// cluster or chart registry. Live storage readiness remains a downstream gate.
func VerifyRookCephRBD(root string) (Report, error) {
	root, err := canonicalRoot(root)
	if err != nil {
		return Report{}, err
	}
	report := Report{Status: "blocked", Profile: "cloudring-rook-ceph-rbd/v1"}
	if _, err := VerifyCSISnapshotAPI(root); err != nil {
		return report, errors.New("canonical CSI snapshot API dependency is invalid")
	}
	repository, err := os.OpenRoot(root)
	if err != nil {
		return report, errors.New("open confined repository root")
	}
	defer repository.Close()

	var objects []object
	for _, stage := range []struct {
		name     string
		resource string
	}{
		{name: "controllers", resource: "resources.yaml"},
		{name: "cluster-example", resource: "release.yaml"},
	} {
		stageObjects, files, readErr := readRookCephRBDStage(repository, stage.name, stage.resource)
		if readErr != nil {
			return report, readErr
		}
		report.Files += files
		objects = append(objects, stageObjects...)
	}
	report.Documents = len(objects)
	if report.Files != 4 || report.Documents != 6 {
		return report, errors.New("Rook-Ceph RBD source inventory is incomplete")
	}
	if err := validateRookCephRBDObjects(objects); err != nil {
		return report, err
	}
	report.Status = "ready"
	report.Checks = []string{
		"controller_and_cluster_stages_separated",
		"rook_and_ceph_versions_pinned",
		"cluster_example_suspended",
		"three_explicit_encrypted_osds",
		"automatic_disk_consumption_disabled",
		"replicated_rbd_pool_ready",
		"rbd_storage_class_fail_closed",
		"single_retained_velero_snapshot_class",
		"cephfs_rgw_and_erasure_coding_disabled",
	}
	return report, nil
}

func readRookCephRBDStage(root *os.Root, stage, resource string) ([]object, int, error) {
	directory := filepath.Join(rookCephRBDProfilePath, stage)
	kustomization, err := readRegular(root, filepath.Join(directory, "kustomization.yaml"))
	if err != nil {
		return nil, 0, err
	}
	var manifest map[string]any
	if err := decodeOne(kustomization, &manifest); err != nil ||
		!exactMappingKeys(manifest, "apiVersion", "kind", "resources") ||
		stringValue(manifest["apiVersion"]) != "kustomize.config.k8s.io/v1beta1" ||
		stringValue(manifest["kind"]) != "Kustomization" ||
		!exactStringSequence(manifest["resources"], resource) {
		return nil, 0, fmt.Errorf("%s stage has an invalid kustomization", stage)
	}
	data, err := readRegular(root, filepath.Join(directory, resource))
	if err != nil {
		return nil, 0, err
	}
	for _, forbidden := range [][]byte{[]byte("REPLACE_WITH"), []byte(":latest"), []byte("example.invalid")} {
		if bytes.Contains(data, forbidden) {
			return nil, 0, fmt.Errorf("%s contains an unresolved or mutable runtime reference", resource)
		}
	}
	objects, err := decodeObjects(data)
	if err != nil {
		return nil, 0, fmt.Errorf("decode %s: %w", resource, err)
	}
	return objects, 2, nil
}

func validateRookCephRBDObjects(objects []object) error {
	index := map[string]object{}
	veleroSnapshotLabels := 0
	for _, item := range objects {
		key := item.Kind + "/" + item.Namespace + "/" + item.Name
		if _, duplicate := index[key]; duplicate {
			return errors.New("duplicate Rook-Ceph manifest object identity")
		}
		index[key] = item
		if nestedString(item.Data, "metadata", "labels", "velero.io/csi-volumesnapshot-class") == "true" {
			veleroSnapshotLabels++
		}
	}
	expected := []string{
		"HelmRelease/rook-ceph/rook-ceph",
		"HelmRelease/rook-ceph/rook-ceph-cluster",
		"HelmRepository/rook-ceph/rook-release",
		"Namespace//rook-ceph",
		"StorageClass//rook-ceph-rbd",
		"VolumeSnapshotClass//rook-ceph-rbd-retain",
	}
	actual := make([]string, 0, len(index))
	for key := range index {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		return errors.New("Rook-Ceph RBD object inventory is not exact")
	}
	require := func(kind, namespace, name string) object {
		return index[kind+"/"+namespace+"/"+name]
	}

	namespace := require("Namespace", "", "rook-ceph")
	if !exactStringMap(nested(namespace.Data, "metadata", "labels"), map[string]string{
		"app.kubernetes.io/part-of":          "cloudring-storage",
		"pod-security.kubernetes.io/enforce": "privileged",
		"pod-security.kubernetes.io/audit":   "baseline",
		"pod-security.kubernetes.io/warn":    "baseline",
	}) {
		return errors.New("Rook-Ceph namespace boundary is invalid")
	}
	repository := require("HelmRepository", "rook-ceph", "rook-release")
	if nestedString(repository.Data, "spec", "url") != "https://charts.rook.io/release" || nestedString(repository.Data, "spec", "interval") != "1h" {
		return errors.New("Rook chart repository is invalid")
	}

	operator := require("HelmRelease", "rook-ceph", "rook-ceph")
	if !exactMappingKeys(nested(operator.Data, "spec"), "interval", "releaseName", "chart", "install", "upgrade", "values") ||
		!exactHelmChart(operator.Data, "rook-ceph", "v1.20.2") ||
		nested(operator.Data, "spec", "valuesFrom") != nil || nested(operator.Data, "spec", "postRenderers") != nil {
		return errors.New("Rook operator Helm release boundary is invalid")
	}
	operatorValues, _ := nested(operator.Data, "spec", "values").(map[string]any)
	if !exactMappingKeys(operatorValues, "image", "crds", "currentNamespaceOnly", "allowLoopDevices", "enableDiscoveryDaemon", "csi", "resources") ||
		nestedString(operatorValues, "image", "tag") != "v1.20.2" || nestedString(operatorValues, "image", "pullPolicy") != "IfNotPresent" ||
		!exactBool(operatorValues, true, "crds", "enabled") || !exactBool(operatorValues, true, "currentNamespaceOnly") ||
		!exactBool(operatorValues, false, "allowLoopDevices") || !exactBool(operatorValues, false, "enableDiscoveryDaemon") ||
		!exactBool(operatorValues, true, "csi", "installCsiOperator") || !exactBool(operatorValues, false, "csi", "serviceMonitor", "enabled") {
		return errors.New("Rook operator version, CRD, discovery, or CSI contract is invalid")
	}

	cluster := require("HelmRelease", "rook-ceph", "rook-ceph-cluster")
	if !exactMappingKeys(nested(cluster.Data, "spec"), "suspend", "interval", "releaseName", "dependsOn", "chart", "install", "upgrade", "values") ||
		!exactBool(cluster.Data, true, "spec", "suspend") || !exactHelmChart(cluster.Data, "rook-ceph-cluster", "v1.20.2") ||
		nested(cluster.Data, "spec", "valuesFrom") != nil || nested(cluster.Data, "spec", "postRenderers") != nil ||
		nestedString(cluster.Data, "metadata", "annotations", "cloudring.org/non-claim") != "example-node-and-device-references-must-be-replaced-before-activation" ||
		nestedString(cluster.Data, "metadata", "annotations", "cloudring.org/requires-stage") != "deploy/kubernetes/storage/csi-snapshot-api/controller" ||
		!exactDependsOn(cluster.Data, "rook-ceph", "rook-ceph") {
		return errors.New("Rook cluster stage activation boundary is invalid")
	}
	values, _ := nested(cluster.Data, "spec", "values").(map[string]any)
	if !exactMappingKeys(values,
		"operatorNamespace", "clusterName", "csiDriverNamePrefix", "cephImage", "toolbox", "monitoring", "cephClusterSpec",
		"cephBlockPools", "cephBlockPoolsVolumeSnapshotClass", "cephFileSystems", "cephFileSystemVolumeSnapshotClass", "cephObjectStores", "cephECBlockPools") ||
		nestedString(values, "operatorNamespace") != "rook-ceph" || nestedString(values, "clusterName") != "rook-ceph" || nestedString(values, "csiDriverNamePrefix") != "" ||
		nestedString(values, "cephImage", "repository") != "quay.io/ceph/ceph" || nestedString(values, "cephImage", "tag") != "v20.2.2" ||
		!exactBool(values, false, "cephImage", "allowUnsupported") || nestedString(values, "cephImage", "imagePullPolicy") != "IfNotPresent" ||
		!exactBool(values, false, "toolbox", "enabled") || !exactBool(values, false, "monitoring", "enabled") ||
		!exactBool(values, false, "monitoring", "createPrometheusRules") {
		return errors.New("Ceph cluster version or optional surface contract is invalid")
	}
	if err := validateRookCephClusterSpec(values); err != nil {
		return err
	}
	if err := validateRookCephRBDPool(values); err != nil {
		return err
	}
	if !emptySequence(nested(values, "cephFileSystems")) || !emptySequence(nested(values, "cephObjectStores")) || !emptySequence(nested(values, "cephECBlockPools")) ||
		!exactBool(values, false, "cephFileSystemVolumeSnapshotClass", "enabled") || !exactBool(values, false, "cephBlockPoolsVolumeSnapshotClass", "enabled") {
		return errors.New("CephFS, RGW, erasure coding, or chart-generated snapshot classes must stay disabled")
	}

	storageClass := require("StorageClass", "", "rook-ceph-rbd")
	if !validateRookCephRBDStorageClass(storageClass.Data) {
		return errors.New("Rook-Ceph RBD StorageClass is invalid")
	}
	snapshotClass := require("VolumeSnapshotClass", "", "rook-ceph-rbd-retain")
	if veleroSnapshotLabels != 1 || !validateRookCephRBDSnapshotClass(snapshotClass.Data) {
		return errors.New("Rook-Ceph RBD Velero snapshot class is invalid")
	}
	return nil
}

func exactHelmChart(release map[string]any, chart, version string) bool {
	chartSpec, ok := nested(release, "spec", "chart", "spec").(map[string]any)
	return ok && exactMappingKeys(chartSpec, "chart", "version", "sourceRef", "interval") &&
		nestedString(release, "spec", "chart", "spec", "chart") == chart &&
		nestedString(release, "spec", "chart", "spec", "version") == version &&
		nestedString(release, "spec", "chart", "spec", "sourceRef", "kind") == "HelmRepository" &&
		nestedString(release, "spec", "chart", "spec", "sourceRef", "name") == "rook-release" &&
		nestedString(release, "spec", "chart", "spec", "sourceRef", "namespace") == "rook-ceph" &&
		nestedString(release, "spec", "chart", "spec", "interval") == "1h"
}

func exactBool(root map[string]any, expected bool, path ...string) bool {
	value, ok := nested(root, path...).(bool)
	return ok && value == expected
}

func exactDependsOn(release map[string]any, name, namespace string) bool {
	items, ok := nested(release, "spec", "dependsOn").([]any)
	if !ok || len(items) != 1 {
		return false
	}
	item, ok := items[0].(map[string]any)
	return ok && exactMappingKeys(item, "name", "namespace") && stringValue(item["name"]) == name && stringValue(item["namespace"]) == namespace
}

func validateRookCephClusterSpec(values map[string]any) error {
	spec, ok := nested(values, "cephClusterSpec").(map[string]any)
	if !ok || !exactMappingKeys(spec, "dataDirHostPath", "skipUpgradeChecks", "continueUpgradeAfterChecksEvenIfNotHealthy", "upgradeOSDRequiresHealthyPGs", "mon", "mgr", "dashboard", "crashCollector", "cleanupPolicy", "storage", "disruptionManagement") ||
		nestedString(values, "cephClusterSpec", "dataDirHostPath") != "/var/lib/rook" ||
		!exactBool(values, false, "cephClusterSpec", "skipUpgradeChecks") || !exactBool(values, false, "cephClusterSpec", "continueUpgradeAfterChecksEvenIfNotHealthy") ||
		!exactBool(values, true, "cephClusterSpec", "upgradeOSDRequiresHealthyPGs") || nestedNumber(values, "cephClusterSpec", "mon", "count") != 3 ||
		!exactBool(values, false, "cephClusterSpec", "mon", "allowMultiplePerNode") || nestedNumber(values, "cephClusterSpec", "mgr", "count") != 2 ||
		!exactBool(values, false, "cephClusterSpec", "mgr", "allowMultiplePerNode") || !exactBool(values, false, "cephClusterSpec", "dashboard", "enabled") ||
		!exactBool(values, false, "cephClusterSpec", "crashCollector", "disable") || nestedString(values, "cephClusterSpec", "cleanupPolicy", "confirmation") != "" ||
		!exactBool(values, false, "cephClusterSpec", "cleanupPolicy", "allowUninstallWithVolumes") ||
		!exactBool(values, true, "cephClusterSpec", "disruptionManagement", "managePodBudgets") || nestedNumber(values, "cephClusterSpec", "disruptionManagement", "osdMaintenanceTimeout") != 30 {
		return errors.New("Ceph HA, upgrade, cleanup, or disruption contract is invalid")
	}
	storage, ok := nested(values, "cephClusterSpec", "storage").(map[string]any)
	if !ok || !exactMappingKeys(storage, "useAllNodes", "useAllDevices", "config", "nodes") ||
		!exactBool(values, false, "cephClusterSpec", "storage", "useAllNodes") || !exactBool(values, false, "cephClusterSpec", "storage", "useAllDevices") ||
		nestedString(values, "cephClusterSpec", "storage", "config", "encryptedDevice") != "true" || !exactSyntheticOSDNodes(nested(values, "cephClusterSpec", "storage", "nodes")) {
		return errors.New("Ceph storage selection must contain exactly three explicit encrypted OSD devices")
	}
	return nil
}

func exactSyntheticOSDNodes(value any) bool {
	nodes, ok := value.([]any)
	if !ok || len(nodes) != 3 {
		return false
	}
	expected := map[string]string{
		"example-storage-node-a": "/dev/disk/by-id/cloudring-example-osd-a",
		"example-storage-node-b": "/dev/disk/by-id/cloudring-example-osd-b",
		"example-storage-node-c": "/dev/disk/by-id/cloudring-example-osd-c",
	}
	for _, rawNode := range nodes {
		node, ok := rawNode.(map[string]any)
		if !ok || !exactMappingKeys(node, "name", "devices") {
			return false
		}
		name := stringValue(node["name"])
		devices, ok := node["devices"].([]any)
		if !ok || len(devices) != 1 {
			return false
		}
		device, ok := devices[0].(map[string]any)
		if !ok || !exactMappingKeys(device, "name") || stringValue(device["name"]) != expected[name] {
			return false
		}
		delete(expected, name)
	}
	return len(expected) == 0
}

func validateRookCephRBDPool(values map[string]any) error {
	pools, ok := nested(values, "cephBlockPools").([]any)
	if !ok || len(pools) != 1 {
		return errors.New("exactly one RBD pool is required")
	}
	pool, ok := pools[0].(map[string]any)
	if !ok || !exactMappingKeys(pool, "name", "spec", "storageClass") || stringValue(pool["name"]) != "tenant-rbd" ||
		nestedString(pool, "spec", "failureDomain") != "host" || nestedNumber(pool, "spec", "replicated", "size") != 3 ||
		!exactBool(pool, true, "spec", "replicated", "requireSafeReplicaSize") || !exactBool(pool, false, "storageClass", "enabled") {
		return errors.New("replicated RBD pool contract is invalid")
	}
	return nil
}

func emptySequence(value any) bool {
	items, ok := value.([]any)
	return ok && len(items) == 0
}

func validateRookCephRBDStorageClass(class map[string]any) bool {
	parameters, ok := nested(class, "parameters").(map[string]any)
	return ok && exactMappingKeys(class, "apiVersion", "kind", "metadata", "provisioner", "parameters", "allowVolumeExpansion", "reclaimPolicy", "volumeBindingMode") &&
		nestedString(class, "apiVersion") == "storage.k8s.io/v1" && nestedString(class, "provisioner") == "rook-ceph.rbd.csi.ceph.com" &&
		exactBool(class, true, "allowVolumeExpansion") && nestedString(class, "reclaimPolicy") == "Delete" && nestedString(class, "volumeBindingMode") == "WaitForFirstConsumer" &&
		nestedString(class, "metadata", "annotations", "storageclass.kubernetes.io/is-default-class") == "false" &&
		exactMappingKeys(parameters, "clusterID", "pool", "imageFormat", "imageFeatures",
			"csi.storage.k8s.io/provisioner-secret-name", "csi.storage.k8s.io/provisioner-secret-namespace",
			"csi.storage.k8s.io/controller-expand-secret-name", "csi.storage.k8s.io/controller-expand-secret-namespace",
			"csi.storage.k8s.io/controller-publish-secret-name", "csi.storage.k8s.io/controller-publish-secret-namespace",
			"csi.storage.k8s.io/node-stage-secret-name", "csi.storage.k8s.io/node-stage-secret-namespace", "csi.storage.k8s.io/fstype") &&
		nestedString(class, "parameters", "clusterID") == "rook-ceph" && nestedString(class, "parameters", "pool") == "tenant-rbd" &&
		nestedString(class, "parameters", "imageFormat") == "2" && nestedString(class, "parameters", "imageFeatures") == "layering" && nestedString(class, "parameters", "csi.storage.k8s.io/fstype") == "ext4" &&
		nestedString(class, "parameters", "csi.storage.k8s.io/provisioner-secret-name") == "rook-csi-rbd-provisioner" && nestedString(class, "parameters", "csi.storage.k8s.io/provisioner-secret-namespace") == "rook-ceph" &&
		nestedString(class, "parameters", "csi.storage.k8s.io/controller-expand-secret-name") == "rook-csi-rbd-provisioner" && nestedString(class, "parameters", "csi.storage.k8s.io/controller-expand-secret-namespace") == "rook-ceph" &&
		nestedString(class, "parameters", "csi.storage.k8s.io/controller-publish-secret-name") == "rook-csi-rbd-provisioner" && nestedString(class, "parameters", "csi.storage.k8s.io/controller-publish-secret-namespace") == "rook-ceph" &&
		nestedString(class, "parameters", "csi.storage.k8s.io/node-stage-secret-name") == "rook-csi-rbd-node" && nestedString(class, "parameters", "csi.storage.k8s.io/node-stage-secret-namespace") == "rook-ceph"
}

func validateRookCephRBDSnapshotClass(class map[string]any) bool {
	parameters, ok := nested(class, "parameters").(map[string]any)
	return ok && exactMappingKeys(class, "apiVersion", "kind", "metadata", "driver", "deletionPolicy", "parameters") &&
		nestedString(class, "apiVersion") == "snapshot.storage.k8s.io/v1" && nestedString(class, "driver") == "rook-ceph.rbd.csi.ceph.com" && nestedString(class, "deletionPolicy") == "Retain" &&
		nestedString(class, "metadata", "annotations", "snapshot.storage.kubernetes.io/is-default-class") == "false" &&
		exactStringMap(nested(class, "metadata", "labels"), map[string]string{
			"app.kubernetes.io/part-of":          "cloudring-storage",
			"velero.io/csi-volumesnapshot-class": "true",
		}) && exactMappingKeys(parameters, "clusterID", "csi.storage.k8s.io/snapshotter-secret-name", "csi.storage.k8s.io/snapshotter-secret-namespace") &&
		nestedString(class, "parameters", "clusterID") == "rook-ceph" && nestedString(class, "parameters", "csi.storage.k8s.io/snapshotter-secret-name") == "rook-csi-rbd-provisioner" &&
		nestedString(class, "parameters", "csi.storage.k8s.io/snapshotter-secret-namespace") == "rook-ceph"
}
