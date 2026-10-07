// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package platformmanifest

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLonghornThreeNodeProfileIsStructurallyReady(t *testing.T) {
	report, err := VerifyLonghornThreeNode(repositoryRoot(t))
	if err != nil {
		t.Fatalf("verify Longhorn three-node profile: %v", err)
	}
	if report.Status != "ready" || report.Files != 47 || report.Documents != 6 || len(report.Checks) != 12 {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestLonghornThreeNodeProfileRejectsUnsafeChanges(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
	}{
		{"remote chart path", "      chart: ./charts/longhorn\n", "      chart: https://charts.longhorn.io/longhorn-1.12.0.tgz\n"},
		{"mutable source kind", "        kind: GitRepository\n", "        kind: HelmRepository\n"},
		{"wrong source reference", "        name: longhorn-charts\n", "        name: mutable-longhorn-charts\n"},
		{"chart-version reconciliation", "      reconcileStrategy: Revision\n", "      reconcileStrategy: ChartVersion\n"},
		{"mutable manager image", "          tag: v1.12.0@sha256:fd245bae2e8254ed475073410f8462e95fab8783dd12d1c084777b5ab53bfb86\n", "          tag: v1.12.0\n"},
		{"mismatched CSI digest", "          tag: v4.12.0@sha256:a814aa4784197116983ea13e376fc691e000a390de9d0b9fca2bc4a2fb7c4a1f\n", "          tag: v4.12.0@sha256:0000000000000000000000000000000000000000000000000000000000000000\n"},
		{"source activation", "  suspend: true\n", "  suspend: false\n"},
		{"chart default class", "      defaultClass: false\n", "      defaultClass: true\n"},
		{"two replicas", "      defaultReplicaCount: '{\"v1\":\"3\",\"v2\":\"3\"}'\n", "      defaultReplicaCount: '{\"v1\":\"2\",\"v2\":\"2\"}'\n"},
		{"soft node anti-affinity", "      replicaSoftAntiAffinity: false\n", "      replicaSoftAntiAffinity: true\n"},
		{"hard zone anti-affinity", "      replicaZoneSoftAntiAffinity: true\n", "      replicaZoneSoftAntiAffinity: false\n"},
		{"degraded creation", "      allowVolumeCreationWithDegradedAvailability: false\n", "      allowVolumeCreationWithDegradedAvailability: true\n"},
		{"usage metrics", "      allowCollectingLonghornUsageMetrics: false\n", "      allowCollectingLonghornUsageMetrics: true\n"},
		{"revision counter disabled", "      disableRevisionCounter: '{\"v1\":\"false\"}'\n", "      disableRevisionCounter: '{\"v1\":\"true\"}'\n"},
		{"v2 engine", "      v2DataEngine: false\n", "      v2DataEngine: true\n"},
		{"wrong provisioner", "provisioner: driver.longhorn.io\n", "provisioner: forbidden.example.csi\n"},
		{"immediate binding", "volumeBindingMode: WaitForFirstConsumer\n", "volumeBindingMode: Immediate\n"},
		{"migratable mode disabled", "  migratable: \"true\"\n", "  migratable: \"false\"\n"},
		{"delete snapshots", "deletionPolicy: Retain\n", "deletionPolicy: Delete\n"},
		{"Longhorn native backup snapshot", "  type: snap\n", "  type: bak\n"},
		{"missing canonical snapshot dependency", "    cloudring.org/requires-stage: deploy/kubernetes/storage/csi-snapshot-api/controller\n", ""},
		{"ui ingress", "    ingress:\n      enabled: false\n", "    ingress:\n      enabled: true\n"},
		{"second Velero selector", "    app.kubernetes.io/part-of: cloudring-storage\n  annotations:\n    storageclass.kubernetes.io/is-default-class: \"false\"\n", "    app.kubernetes.io/part-of: cloudring-storage\n    velero.io/csi-volumesnapshot-class: \"true\"\n  annotations:\n    storageclass.kubernetes.io/is-default-class: \"false\"\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := copyLonghornThreeNodeProfile(t)
			data := readLonghornThreeNodeProfileFile(t, root, "runtime/resources.yaml")
			data = replaceOnce(t, data, []byte(test.old), []byte(test.replacement))
			writeLonghornThreeNodeProfileFile(t, root, "runtime/resources.yaml", data)
			if _, err := VerifyLonghornThreeNode(root); err == nil {
				t.Fatalf("unsafe change %q was accepted", test.name)
			}
		})
	}
}

func TestLonghornThreeNodeProfileRejectsMutableOrMismatchedGitSource(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
	}{
		{"branch instead of commit", "  ref:\n    commit: f8def0504bf3f5f26c342941c9e4532b44830ebe\n", "  ref:\n    branch: v1.12.x\n"},
		{"tag instead of commit", "  ref:\n    commit: f8def0504bf3f5f26c342941c9e4532b44830ebe\n", "  ref:\n    tag: longhorn-1.12.0\n"},
		{"missing commit", "  ref:\n    commit: f8def0504bf3f5f26c342941c9e4532b44830ebe\n", "  ref: {}\n"},
		{"mismatched commit", "    commit: f8def0504bf3f5f26c342941c9e4532b44830ebe\n", "    commit: 0000000000000000000000000000000000000000\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := copyLonghornThreeNodeProfile(t)
			data := readLonghornThreeNodeProfileFile(t, root, "runtime/resources.yaml")
			data = replaceOnce(t, data, []byte(test.old), []byte(test.replacement))
			writeLonghornThreeNodeProfileFile(t, root, "runtime/resources.yaml", data)
			if _, err := VerifyLonghornThreeNode(root); err == nil {
				t.Fatal("mutable, absent, or mismatched Git source commit was accepted")
			}
		})
	}
}

func TestLonghornThreeNodeProfileRejectsVendoredChartDrift(t *testing.T) {
	root := copyLonghornThreeNodeProfile(t)
	path := filepath.Join(longhornVendoredChartPath, "Chart.yaml")
	data := readRepositoryFile(t, root, path)
	data = replaceOnce(t, data, []byte("version: 1.12.0\n"), []byte("version: 1.12.1\n"))
	writeRepositoryFile(t, root, path, data)
	if _, err := VerifyLonghornThreeNode(root); err == nil {
		t.Fatal("vendored chart digest drift was accepted")
	}
}

func TestLonghornThreeNodeProfileRejectsExtraVendoredFile(t *testing.T) {
	root := copyLonghornThreeNodeProfile(t)
	writeRepositoryFile(t, root, filepath.Join(longhornVendoredChartPath, "unreviewed.txt"), []byte("unreviewed\n"))
	if _, err := VerifyLonghornThreeNode(root); err == nil {
		t.Fatal("extra vendored chart file was accepted")
	}
}

func TestLonghornThreeNodeHelmRenderHasExactDigestPinnedImageInventory(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not installed; the verifier still checks the complete chart image reference and Helm values inventories")
	}
	root := repositoryRoot(t)
	repository, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	objects, _, err := readLonghornThreeNodeStage(repository)
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	for _, object := range objects {
		if object.Kind == "HelmRelease" && object.Namespace == "longhorn-system" && object.Name == "longhorn" {
			values, _ = nested(object.Data, "spec", "values").(map[string]any)
		}
	}
	if values == nil {
		t.Fatal("Longhorn Helm values are missing")
	}
	valuesYAML, err := yaml.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	valuesPath := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(valuesPath, valuesYAML, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(helm, "template", "longhorn", filepath.Join(root, longhornVendoredChartPath), "--namespace", "longhorn-system", "--values", valuesPath) // #nosec G204 -- executable is resolved locally and every argument is test-owned.
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("render Longhorn chart: %v: %s", err, output)
	}
	pattern := regexp.MustCompile(`docker[.]io/longhornio/[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}`)
	actualSet := map[string]struct{}{}
	for _, match := range pattern.FindAllString(string(output), -1) {
		actualSet[match] = struct{}{}
	}
	actual := make([]string, 0, len(actualSet))
	for image := range actualSet {
		actual = append(actual, image)
	}
	expected := make([]string, 0, len(reviewedLonghornRuntimeImages))
	for _, image := range reviewedLonghornRuntimeImages {
		expected = append(expected, "docker.io/"+image.Repository+":"+image.Tag+"@"+image.Digest)
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("rendered image inventory differs\nactual:\n%s\nexpected:\n%s", strings.Join(actual, "\n"), strings.Join(expected, "\n"))
	}
}

func TestLonghornThreeNodeProfileRejectsDuplicateYAMLKeys(t *testing.T) {
	root := copyLonghornThreeNodeProfile(t)
	data := readLonghornThreeNodeProfileFile(t, root, "runtime/resources.yaml")
	data = append(data, []byte("driver: driver.longhorn.io\n")...)
	writeLonghornThreeNodeProfileFile(t, root, "runtime/resources.yaml", data)
	if _, err := VerifyLonghornThreeNode(root); err == nil {
		t.Fatal("duplicate YAML key was accepted")
	}
}

func copyLonghornThreeNodeProfile(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	source, err := os.OpenRoot(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	chartPaths, err := confinedRegularFiles(source, longhornVendoredChartPath)
	if err != nil {
		t.Fatal(err)
	}
	for index, path := range chartPaths {
		chartPaths[index] = filepath.Join(longhornVendoredChartPath, path)
	}
	for _, sourcePath := range append(
		[]string{
			filepath.Join(longhornThreeNodeProfilePath, "runtime/kustomization.yaml"),
			filepath.Join(longhornThreeNodeProfilePath, "runtime/resources.yaml"),
			runtimeChartSupplyChainPath,
			filepath.Join(longhornVendoredRoot, "LICENSE"),
			filepath.Join(longhornVendoredRoot, "UPSTREAM.json"),
		},
		append(csiSnapshotAPITestFiles(), chartPaths...)...,
	) {
		data, err := source.ReadFile(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		if err := destination.MkdirAll(filepath.Dir(sourcePath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := destination.WriteFile(sourcePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func readRepositoryFile(t *testing.T, root, relative string) []byte {
	t.Helper()
	repository, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	data, err := repository.ReadFile(relative)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeRepositoryFile(t *testing.T, root, relative string, data []byte) {
	t.Helper()
	repository, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.MkdirAll(filepath.Dir(relative), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := repository.WriteFile(relative, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readLonghornThreeNodeProfileFile(t *testing.T, root, relative string) []byte {
	t.Helper()
	repository, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	data, err := repository.ReadFile(filepath.Join(longhornThreeNodeProfilePath, relative))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeLonghornThreeNodeProfileFile(t *testing.T, root, relative string, data []byte) {
	t.Helper()
	repository, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.WriteFile(filepath.Join(longhornThreeNodeProfilePath, relative), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
