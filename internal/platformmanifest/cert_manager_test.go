// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package platformmanifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCertManagerProfileIsStructurallyReady(t *testing.T) {
	report, err := VerifyCertManager(repositoryRoot(t))
	if err != nil {
		t.Fatalf("verify cert-manager profile: %v", err)
	}
	if report.Status != "ready" || report.Files != 4 || report.Documents != 3 || len(report.Checks) != 9 {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestCertManagerProfileRejectsUnsafeChanges(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		old         string
		replacement string
	}{
		{"active reusable release", "controllers/resources.yaml", "  suspend: true\n", "  suspend: false\n"},
		{"wrong OCI manifest digest", "controllers/resources.yaml", certManagerOCIManifestDigest, "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		{"untrusted OCI repository", "controllers/resources.yaml", "  url: oci://quay.io/jetstack/charts/cert-manager\n", "  url: oci://registry.invalid/cert-manager\n"},
		{"mutable source kind", "controllers/resources.yaml", "kind: OCIRepository\n", "kind: HelmRepository\n"},
		{"wrong chart reference", "controllers/resources.yaml", "  chartRef:\n    kind: OCIRepository\n    name: cert-manager\n", "  chartRef:\n    kind: OCIRepository\n    name: unreviewed\n"},
		{"aggregate roles enabled", "controllers/resources.yaml", "        aggregateClusterRoles: false\n", "        aggregateClusterRoles: true\n"},
		{"CRDs disabled", "controllers/resources.yaml", "    crds:\n      enabled: true\n      keep: true\n", "    crds:\n      enabled: false\n      keep: true\n"},
		{"CRDs not retained", "controllers/resources.yaml", "    crds:\n      enabled: true\n      keep: true\n", "    crds:\n      enabled: true\n      keep: false\n"},
		{"unsafe CRD upgrade", "controllers/resources.yaml", "  upgrade:\n    crds: CreateReplace\n", "  upgrade:\n    crds: Skip\n"},
		{"upgrade cleanup disabled", "controllers/resources.yaml", "  upgrade:\n    crds: CreateReplace\n    cleanupOnFail: true\n", "  upgrade:\n    crds: CreateReplace\n    cleanupOnFail: false\n"},
		{"controller single replica", "controllers/resources.yaml", "    replicaCount: 3\n", "    replicaCount: 1\n"},
		{"controller weak PDB", "controllers/resources.yaml", "    podDisruptionBudget:\n      enabled: true\n      minAvailable: 2\n", "    podDisruptionBudget:\n      enabled: true\n      minAvailable: 1\n"},
		{"controller soft spread", "controllers/resources.yaml", "    topologySpreadConstraints:\n      - maxSkew: 1\n        topologyKey: kubernetes.io/hostname\n        whenUnsatisfiable: DoNotSchedule\n", "    topologySpreadConstraints:\n      - maxSkew: 1\n        topologyKey: kubernetes.io/hostname\n        whenUnsatisfiable: ScheduleAnyway\n"},
		{"mutable controller image", "controllers/resources.yaml", "      tag: v1.21.0\n      digest: sha256:e370f7800a53078e9d74324287a7d52b553864e55f5b4e521f911c3f6c7da203\n", "      tag: latest\n      digest: sha256:e370f7800a53078e9d74324287a7d52b553864e55f5b4e521f911c3f6c7da203\n"},
		{"wrong controller digest", "controllers/resources.yaml", "sha256:e370f7800a53078e9d74324287a7d52b553864e55f5b4e521f911c3f6c7da203", "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		{"webhook single replica", "controllers/resources.yaml", "    webhook:\n      replicaCount: 3\n", "    webhook:\n      replicaCount: 1\n"},
		{"webhook weak PDB", "controllers/resources.yaml", "    webhook:\n      replicaCount: 3\n      timeoutSeconds: 10\n      strategy:\n        type: RollingUpdate\n        rollingUpdate:\n          maxSurge: 1\n          maxUnavailable: 1\n      podDisruptionBudget:\n        enabled: true\n        minAvailable: 2\n", "    webhook:\n      replicaCount: 3\n      timeoutSeconds: 10\n      strategy:\n        type: RollingUpdate\n        rollingUpdate:\n          maxSurge: 1\n          maxUnavailable: 1\n      podDisruptionBudget:\n        enabled: true\n        minAvailable: 1\n"},
		{"wrong webhook digest", "controllers/resources.yaml", "sha256:c33cca307541e2d58861a55b1af5f390b7e19c8741e48b433693b73a7cce88b3", "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		{"CA injector disabled", "controllers/resources.yaml", "    cainjector:\n      enabled: true\n", "    cainjector:\n      enabled: false\n"},
		{"CA injector single replica", "controllers/resources.yaml", "    cainjector:\n      enabled: true\n      replicaCount: 3\n", "    cainjector:\n      enabled: true\n      replicaCount: 1\n"},
		{"CA injector weak PDB", "controllers/resources.yaml", "    cainjector:\n      enabled: true\n      replicaCount: 3\n      strategy:\n        type: RollingUpdate\n        rollingUpdate:\n          maxSurge: 1\n          maxUnavailable: 1\n      podDisruptionBudget:\n        enabled: true\n        minAvailable: 2\n", "    cainjector:\n      enabled: true\n      replicaCount: 3\n      strategy:\n        type: RollingUpdate\n        rollingUpdate:\n          maxSurge: 1\n          maxUnavailable: 1\n      podDisruptionBudget:\n        enabled: true\n        minAvailable: 1\n"},
		{"wrong CA injector digest", "controllers/resources.yaml", "sha256:ad1dcc5b2fccc420f9b3fbee7ce8a869450c540fd4f2f41de2d95b1ca0c4d701", "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		{"startup check disabled", "controllers/resources.yaml", "    startupapicheck:\n      enabled: true\n", "    startupapicheck:\n      enabled: false\n"},
		{"wrong startup image digest", "controllers/resources.yaml", "sha256:68b3c5029dc63e64a6b6435337d7dc0eb169f889a48a02d999d1f22f31865b33", "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		{"wrong ACME solver digest", "controllers/resources.yaml", "sha256:33ebbc2688578e37bd48dcc5b6b1f1362c919dff44fe5e5f602532a2d37d514f", "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		{"weakened namespace policy", "controllers/resources.yaml", "    pod-security.kubernetes.io/enforce: restricted\n", "    pod-security.kubernetes.io/enforce: baseline\n"},
		{"added Linux capability", "controllers/resources.yaml", "    containerSecurityContext:\n      allowPrivilegeEscalation: false\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop:\n          - ALL\n", "    containerSecurityContext:\n      allowPrivilegeEscalation: false\n      readOnlyRootFilesystem: true\n      capabilities:\n        add:\n          - NET_ADMIN\n        drop:\n          - ALL\n"},
		{"removed non-claim", "controllers/resources.yaml", "downstream-live-issuance-renewal-webhook-and-one-node-loss-evidence-required", "source-ready"},
		{"render-time values", "controllers/resources.yaml", "  values:\n", "  valuesFrom: []\n  values:\n"},
		{"remote kustomize resource", "controllers/kustomization.yaml", "  - resources.yaml\n", "  - https://example.invalid/resources.yaml\n"},
		{"missing live non-claim documentation", "README.md", "does not prove", "proves"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := copyCertManagerProfile(t)
			path := filepath.Join(certManagerProfilePath, test.path)
			data := readCertManagerFile(t, root, path)
			data = replaceOnce(t, data, []byte(test.old), []byte(test.replacement))
			writeCertManagerFile(t, root, path, data)
			if _, err := VerifyCertManager(root); err == nil {
				t.Fatalf("unsafe change %q was accepted", test.name)
			}
		})
	}
}

func TestCertManagerProfileRejectsDuplicateYAMLKeys(t *testing.T) {
	root := copyCertManagerProfile(t)
	path := filepath.Join(certManagerProfilePath, "controllers", "resources.yaml")
	data := readCertManagerFile(t, root, path)
	data = append(data, []byte("spec: {}\n")...)
	writeCertManagerFile(t, root, path, data)
	if _, err := VerifyCertManager(root); err == nil {
		t.Fatal("duplicate YAML key was accepted")
	}
}

func copyCertManagerProfile(t *testing.T) string {
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
	for _, path := range []string{
		filepath.Join(certManagerProfilePath, "README.md"),
		filepath.Join(certManagerProfilePath, "controllers/kustomization.yaml"),
		filepath.Join(certManagerProfilePath, "controllers/resources.yaml"),
		runtimeChartSupplyChainPath,
	} {
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

func readCertManagerFile(t *testing.T, root, relative string) []byte {
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

func writeCertManagerFile(t *testing.T, root, relative string, data []byte) {
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
