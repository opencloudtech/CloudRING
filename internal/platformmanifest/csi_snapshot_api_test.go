// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package platformmanifest

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCSISnapshotAPIIsStructurallyReady(t *testing.T) {
	report, err := VerifyCSISnapshotAPI(repositoryRoot(t))
	if err != nil {
		t.Fatalf("verify CSI snapshot API: %v", err)
	}
	if report.Status != "ready" || report.Files != 7 || report.Documents != 10 || len(report.Checks) != 10 {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestCSISnapshotAPIRejectsUnsafeControllerChanges(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		old         string
		replacement string
	}{
		{"remote CRD source", "crds/kustomization.yaml", "  - snapshot.storage.k8s.io_volumesnapshots.yaml\n", "  - https://example.invalid/volumesnapshots.yaml\n"},
		{"mutable controller image", "controller/resources.yaml", csiSnapshotControllerImage, "registry.k8s.io/sig-storage/snapshot-controller:latest"},
		{"wrong upstream commit", "controller/resources.yaml", csiSnapshotCommit, "0000000000000000000000000000000000000000"},
		{"wrong upstream RBAC checksum", "controller/resources.yaml", csiSnapshotUpstreamRBACSHA256, "0000000000000000000000000000000000000000000000000000000000000000"},
		{"aggregated cluster role", "controller/resources.yaml", "rules:\n  - apiGroups: [\"\"]\n", "aggregationRule:\n  clusterRoleSelectors: []\nrules:\n  - apiGroups: [\"\"]\n"},
		{"missing CRD dependency", "controller/resources.yaml", "    cloudring.org/requires-stage: deploy/kubernetes/storage/csi-snapshot-api/crds\n", ""},
		{"single replica", "controller/resources.yaml", "  replicas: 2\n", "  replicas: 1\n"},
		{"available replica removed during rollout", "controller/resources.yaml", "      maxUnavailable: 0\n", "      maxUnavailable: 1\n"},
		{"leader election disabled", "controller/resources.yaml", "            - --leader-election=true\n", "            - --leader-election=false\n"},
		{"wrong health port", "controller/resources.yaml", "              containerPort: 8080\n", "              containerPort: 8081\n"},
		{"one topology domain accepted", "controller/resources.yaml", "          minDomains: 2\n", "          minDomains: 1\n"},
		{"soft topology spread", "controller/resources.yaml", "          whenUnsatisfiable: DoNotSchedule\n", "          whenUnsatisfiable: ScheduleAnyway\n"},
		{"wildcard RBAC", "controller/resources.yaml", "    resources: [\"persistentvolumes\"]\n", "    resources: [\"*\"]\n"},
		{"group snapshot RBAC", "controller/resources.yaml", "  - apiGroups: [\"snapshot.storage.k8s.io\"]\n", "  - apiGroups: [\"groupsnapshot.storage.k8s.io\"]\n"},
		{"privilege escalation", "controller/resources.yaml", "            allowPrivilegeEscalation: false\n", "            allowPrivilegeEscalation: true\n"},
		{"writable root", "controller/resources.yaml", "            readOnlyRootFilesystem: true\n", "            readOnlyRootFilesystem: false\n"},
		{"PDB disabled", "controller/resources.yaml", "  minAvailable: 1\n", "  minAvailable: 0\n"},
		{"live readiness overclaim", "README.md", "does not prove", "proves"},
		{"unordered activation", "README.md", "make `controller` depend on the Ready CRD Kustomization", "apply controller at the same time as CRDs"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := copyCSISnapshotAPI(t)
			path := filepath.Join(csiSnapshotAPIProfilePath, test.path)
			data := readCSISnapshotAPITestFile(t, root, path)
			data = replaceOnce(t, data, []byte(test.old), []byte(test.replacement))
			writeCSISnapshotAPITestFile(t, root, path, data)
			if _, err := VerifyCSISnapshotAPI(root); err == nil {
				t.Fatalf("unsafe change %q was accepted", test.name)
			}
		})
	}
}

func TestCSISnapshotAPIRejectsAnyVendoredCRDDrift(t *testing.T) {
	for _, crd := range csiSnapshotCRDs {
		t.Run(crd.name, func(t *testing.T) {
			root := copyCSISnapshotAPI(t)
			path := filepath.Join(csiSnapshotAPIProfilePath, "crds", crd.file)
			data := append(readCSISnapshotAPITestFile(t, root, path), []byte("# unreviewed drift\n")...)
			writeCSISnapshotAPITestFile(t, root, path, data)
			if _, err := VerifyCSISnapshotAPI(root); err == nil {
				t.Fatal("vendored CRD drift was accepted")
			}
		})
	}
}

func TestCSISnapshotAPIRejectsDuplicateControllerOwner(t *testing.T) {
	root := copyCSISnapshotAPI(t)
	path := filepath.Join(root, "deploy", "kubernetes", "storage", "other-profile", "resources.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: snapshot-controller\n  namespace: kube-system\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCSISnapshotAPI(root); err == nil {
		t.Fatal("second snapshot-controller owner was accepted")
	}
}

func TestCSISnapshotAPIRejectsDuplicateYAMLKeys(t *testing.T) {
	root := copyCSISnapshotAPI(t)
	path := filepath.Join(csiSnapshotAPIProfilePath, "controller", "resources.yaml")
	data := append(readCSISnapshotAPITestFile(t, root, path), []byte("spec: {}\n")...)
	writeCSISnapshotAPITestFile(t, root, path, data)
	if _, err := VerifyCSISnapshotAPI(root); err == nil {
		t.Fatal("duplicate YAML key was accepted")
	}
}

func TestCSISnapshotAPIKustomizeStagesRender(t *testing.T) {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Skip("kubectl is not installed; CI platform-manifests job renders both stages")
	}
	root := repositoryRoot(t)
	for _, test := range []struct {
		stage     string
		documents int
	}{
		{stage: "crds", documents: 3},
		{stage: "controller", documents: 7},
	} {
		t.Run(test.stage, func(t *testing.T) {
			command := exec.Command(kubectl, "kustomize", filepath.Join(root, csiSnapshotAPIProfilePath, test.stage)) // #nosec G204 -- executable is resolved locally and stage is selected from the fixed test-owned table above.
			output, err := command.Output()
			if err != nil {
				t.Fatalf("render %s stage: %v", test.stage, err)
			}
			objects, err := decodeObjects(output)
			if err != nil {
				t.Fatalf("decode rendered %s stage: %v", test.stage, err)
			}
			if len(objects) != test.documents {
				t.Fatalf("rendered %s stage has %d documents, want %d", test.stage, len(objects), test.documents)
			}
		})
	}
}

func csiSnapshotAPITestFiles() []string {
	files := []string{
		filepath.Join(csiSnapshotAPIProfilePath, "README.md"),
		filepath.Join(csiSnapshotAPIProfilePath, "crds", "kustomization.yaml"),
		filepath.Join(csiSnapshotAPIProfilePath, "controller", "kustomization.yaml"),
		filepath.Join(csiSnapshotAPIProfilePath, "controller", "resources.yaml"),
	}
	for _, crd := range csiSnapshotCRDs {
		files = append(files, filepath.Join(csiSnapshotAPIProfilePath, "crds", crd.file))
	}
	return files
}

func copyCSISnapshotAPI(t *testing.T) string {
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
	for _, path := range csiSnapshotAPITestFiles() {
		data, err := source.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := destination.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := destination.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func readCSISnapshotAPITestFile(t *testing.T, root, relative string) []byte {
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

func writeCSISnapshotAPITestFile(t *testing.T, root, relative string, data []byte) {
	t.Helper()
	repository, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.WriteFile(relative, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
