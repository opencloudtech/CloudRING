// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package platformmanifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRookCephRBDProfileIsStructurallyReady(t *testing.T) {
	report, err := VerifyRookCephRBD(repositoryRoot(t))
	if err != nil {
		t.Fatalf("verify Rook-Ceph RBD profile: %v", err)
	}
	if report.Status != "ready" || report.Files != 4 || report.Documents != 6 || len(report.Checks) != 9 {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestRookCephRBDProfileRejectsUnsafeChanges(t *testing.T) {
	tests := []struct {
		name        string
		file        string
		old         string
		replacement string
	}{
		{
			name:        "mutable operator chart",
			file:        "controllers/resources.yaml",
			old:         "      version: v1.20.2\n",
			replacement: "      version: latest\n",
		},
		{
			name:        "mutable Ceph image",
			file:        "cluster-example/release.yaml",
			old:         "      tag: v20.2.2\n",
			replacement: "      tag: latest\n",
		},
		{
			name:        "all nodes",
			file:        "cluster-example/release.yaml",
			old:         "        useAllNodes: false\n",
			replacement: "        useAllNodes: true\n",
		},
		{
			name:        "all devices",
			file:        "cluster-example/release.yaml",
			old:         "        useAllDevices: false\n",
			replacement: "        useAllDevices: true\n",
		},
		{
			name: "fewer than three explicit nodes",
			file: "cluster-example/release.yaml",
			old: "          - name: example-storage-node-c\n" +
				"            devices:\n" +
				"              - name: /dev/disk/by-id/cloudring-example-osd-c\n",
			replacement: "",
		},
		{
			name:        "unencrypted devices",
			file:        "cluster-example/release.yaml",
			old:         "          encryptedDevice: \"true\"\n",
			replacement: "          encryptedDevice: \"false\"\n",
		},
		{
			name:        "non-host failure domain",
			file:        "cluster-example/release.yaml",
			old:         "          failureDomain: host\n",
			replacement: "          failureDomain: osd\n",
		},
		{
			name:        "two replicas",
			file:        "cluster-example/release.yaml",
			old:         "            size: 3\n",
			replacement: "            size: 2\n",
		},
		{
			name:        "default storage class",
			file:        "cluster-example/release.yaml",
			old:         "    storageclass.kubernetes.io/is-default-class: \"false\"\n",
			replacement: "    storageclass.kubernetes.io/is-default-class: \"true\"\n",
		},
		{
			name:        "immediate binding",
			file:        "cluster-example/release.yaml",
			old:         "volumeBindingMode: WaitForFirstConsumer\n",
			replacement: "volumeBindingMode: Immediate\n",
		},
		{
			name:        "wrong provisioner",
			file:        "cluster-example/release.yaml",
			old:         "provisioner: rook-ceph.rbd.csi.ceph.com\n",
			replacement: "provisioner: forbidden.example.csi\n",
		},
		{
			name:        "missing node-stage secret",
			file:        "cluster-example/release.yaml",
			old:         "  csi.storage.k8s.io/node-stage-secret-name: rook-csi-rbd-node\n",
			replacement: "",
		},
		{
			name:        "wrong snapshot driver",
			file:        "cluster-example/release.yaml",
			old:         "driver: rook-ceph.rbd.csi.ceph.com\n",
			replacement: "driver: forbidden.example.csi\n",
		},
		{
			name:        "delete snapshots",
			file:        "cluster-example/release.yaml",
			old:         "deletionPolicy: Retain\n",
			replacement: "deletionPolicy: Delete\n",
		},
		{
			name:        "second Velero snapshot selector",
			file:        "cluster-example/release.yaml",
			old:         "    app.kubernetes.io/part-of: cloudring-storage\n  annotations:\n    storageclass.kubernetes.io/is-default-class: \"false\"\n",
			replacement: "    app.kubernetes.io/part-of: cloudring-storage\n    velero.io/csi-volumesnapshot-class: \"true\"\n  annotations:\n    storageclass.kubernetes.io/is-default-class: \"false\"\n",
		},
		{
			name:        "CephFS enabled",
			file:        "cluster-example/release.yaml",
			old:         "    cephFileSystems: []\n",
			replacement: "    cephFileSystems:\n      - name: forbidden-cephfs\n",
		},
		{
			name:        "chart snapshot class enabled",
			file:        "cluster-example/release.yaml",
			old:         "    cephBlockPoolsVolumeSnapshotClass:\n      enabled: false\n",
			replacement: "    cephBlockPoolsVolumeSnapshotClass:\n      enabled: true\n",
		},
		{
			name:        "cluster activated from example",
			file:        "cluster-example/release.yaml",
			old:         "  suspend: true\n",
			replacement: "  suspend: false\n",
		},
		{
			name:        "missing canonical snapshot dependency",
			file:        "cluster-example/release.yaml",
			old:         "    cloudring.org/requires-stage: deploy/kubernetes/storage/csi-snapshot-api/controller\n",
			replacement: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := copyRookCephRBDProfile(t)
			data := readRookCephRBDProfileFile(t, root, test.file)
			data = replaceOnce(t, data, []byte(test.old), []byte(test.replacement))
			writeRookCephRBDProfileFile(t, root, test.file, data)
			if _, err := VerifyRookCephRBD(root); err == nil {
				t.Fatalf("unsafe change %q was accepted", test.name)
			}
		})
	}
}

func TestRookCephRBDProfileRejectsDuplicateYAMLKeys(t *testing.T) {
	root := copyRookCephRBDProfile(t)
	path := "cluster-example/release.yaml"
	data := readRookCephRBDProfileFile(t, root, path)
	data = append(data, []byte("driver: rook-ceph.rbd.csi.ceph.com\n")...)
	writeRookCephRBDProfileFile(t, root, path, data)
	if _, err := VerifyRookCephRBD(root); err == nil {
		t.Fatal("duplicate YAML key was accepted")
	}
}

func copyRookCephRBDProfile(t *testing.T) string {
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
	for _, sourcePath := range append(
		[]string{
			filepath.Join(rookCephRBDProfilePath, "controllers/kustomization.yaml"),
			filepath.Join(rookCephRBDProfilePath, "controllers/resources.yaml"),
			filepath.Join(rookCephRBDProfilePath, "cluster-example/kustomization.yaml"),
			filepath.Join(rookCephRBDProfilePath, "cluster-example/release.yaml"),
		},
		csiSnapshotAPITestFiles()...,
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

func readRookCephRBDProfileFile(t *testing.T, root, relative string) []byte {
	t.Helper()
	repository, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	data, err := repository.ReadFile(filepath.Join(rookCephRBDProfilePath, relative))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeRookCephRBDProfileFile(t *testing.T, root, relative string, data []byte) {
	t.Helper()
	repository, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.WriteFile(filepath.Join(rookCephRBDProfilePath, relative), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
