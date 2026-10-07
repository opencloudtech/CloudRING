// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package platformmanifest

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretManagerProfileIsStructurallyReady(t *testing.T) {
	root := repositoryRoot(t)
	report, err := VerifySecretManager(root)
	if err != nil {
		t.Fatalf("verify secret-manager profile: %v", err)
	}
	if report.Status != "ready" || report.Documents != 33 || len(report.Checks) != 9 {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestSecretManagerProfileRejectsWidenedBootstrapExecutorRBAC(t *testing.T) {
	root := copyProfile(t)
	path := filepath.Join("consumer-example", "bootstrap-executor.yaml")
	data, err := readProfileFile(root, path)
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("      - 'cloudring-openbao-exec-6434a933d18dc631c365fc81739ee121c36bd9ac'\n    verbs:\n      - get\n      - update"), []byte("    verbs:\n      - get\n      - update\n      - create"))
	if err := writeProfileFile(root, path, data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "apply executor boundary") {
		t.Fatalf("widened bootstrap executor RBAC was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsPreclaimedBootstrapLease(t *testing.T) {
	root := copyProfile(t)
	path := filepath.Join("consumer-example", "bootstrap-executor.yaml")
	data, err := readProfileFile(root, path)
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("spec: {}"), []byte("spec:\n  holderIdentity: stale-holder"))
	if err := writeProfileFile(root, path, data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "apply executor boundary") {
		t.Fatalf("preclaimed bootstrap Lease was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsMutableImage(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("2.5.5@sha256:6150c4a6b62067db6141c8da7a6a6b5763f4f47c315343d0c848b40fecdfd452"), []byte("2.5.5"))
	if err := writeProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil {
		t.Fatal("mutable OpenBao image was accepted")
	}
}

func TestSecretManagerProfileRejectsDuplicateYAMLKeys(t *testing.T) {
	root := copyProfile(t)
	profile, err := os.OpenRoot(filepath.Join(root, profilePath))
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	file, err := profile.OpenFile(filepath.Join("store", "platform-secrets.yaml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("kind: ClusterSecretStore\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil {
		t.Fatal("duplicate YAML key was accepted")
	}
}

func TestSecretManagerProfileRejectsKustomizeTransformations(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("consumer-example", "kustomization.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("resources:\n"), []byte(`patches:
  - target:
      kind: Role
      name: cloudring-openbao-reader-token-request
    patch: |-
      - op: replace
        path: /rules/0/resourceNames/0
        value: privileged-service
resources:
`))
	if err := writeProfileFile(root, filepath.Join("consumer-example", "kustomization.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "invalid kustomization") {
		t.Fatalf("Kustomize RBAC transformation was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsDisabledListenerTLS(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("tls_disable        = 0"), []byte("tls_disable        = 1"))
	if err := writeProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil {
		t.Fatal("disabled OpenBao listener TLS was accepted")
	}
}

func TestSecretManagerProfileRejectsObsoleteDisableMlock(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("            ui = false\n"), []byte("            ui = false\n            disable_mlock = true\n"))
	if err := writeProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil {
		t.Fatal("obsolete OpenBao disable_mlock setting was accepted")
	}
}

func TestSecretManagerProfileRejectsCommentMaskedListenerTLS(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("tls_disable        = 0"), []byte("# tls_disable        = 0\n              tls_disable        = 1"))
	if err := writeProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil {
		t.Fatal("comment-masked disabled OpenBao listener TLS was accepted")
	}
}

func TestSecretManagerProfileRejectsMissingListenerTLSSetting(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("              tls_disable        = 0\n"), nil)
	if err := writeProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil {
		t.Fatal("missing OpenBao listener TLS setting was accepted")
	}
}

func TestSecretManagerProfileRejectsMissingPersistentAudit(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte(persistentAuditHCL), nil)
	if err := writeProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "persistent audit") {
		t.Fatalf("missing OpenBao persistent audit was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsUnsafePersistentAudit(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
	}{
		{name: "description", old: `description = "CloudRING persistent audit"`, replacement: `description = "Unreviewed audit"`},
		{name: "path", old: `file_path = "/openbao/audit/audit.log"`, replacement: `file_path = "/tmp/audit.log"`},
		{name: "mode", old: `mode      = "0600"`, replacement: `mode      = "0666"`},
		{name: "raw payloads", old: `log_raw   = "false"`, replacement: `log_raw   = "true"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := copyProfile(t)
			data, err := readProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			data = replaceOnce(t, data, []byte(test.old), []byte(test.replacement))
			if err := writeProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"), data); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "persistent audit") {
				t.Fatalf("unsafe OpenBao persistent audit was accepted: %v", err)
			}
		})
	}
}

func TestSecretManagerProfileRejectsMissingServingCertificate(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("runtime", "tls.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("kind: Certificate\nmetadata:\n  name: openbao-server"), []byte("kind: ConfigMap\nmetadata:\n  name: openbao-server"))
	if err := writeProfileFile(root, filepath.Join("runtime", "tls.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil {
		t.Fatal("missing OpenBao serving Certificate was accepted")
	}
}

func TestOpenBaoReadinessPostRendererProducesExactVerifiedTLSCommand(t *testing.T) {
	data, err := readProfileFile(repositoryRoot(t), filepath.Join("runtime", "openbao-release.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	objects, err := decodeObjects(data)
	if err != nil {
		t.Fatal(err)
	}
	var release map[string]any
	for _, item := range objects {
		if item.Kind == "HelmRelease" && item.Name == "openbao" {
			release = item.Data
		}
	}
	command, err := openBaoReadinessPostRenderCommand(release)
	if err != nil {
		t.Fatalf("validate OpenBao readiness post-renderer: %v", err)
	}
	want := []string{"/bin/sh", "-ec", openBaoReadinessShellCommand}
	if strings.Join(command, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("unexpected rendered readiness command: %#v", command)
	}
	if strings.Contains(strings.Join(command, " "), "tls-skip-verify") {
		t.Fatalf("rendered readiness command disables TLS verification: %#v", command)
	}
}

func TestSecretManagerProfileRejectsClusterStoreOutsidePrivilegedNamespace(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("store", "platform-secrets.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("    - namespaces:\n        - external-secrets"), []byte("    - namespaces:\n        - tenant-workload"))
	if err := writeProfileFile(root, filepath.Join("store", "platform-secrets.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "privileged namespace boundary") {
		t.Fatalf("unsafe ClusterSecretStore namespace boundary was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsNonActiveClusterStoreService(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("store", "platform-secrets.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("server: https://openbao-active.openbao.svc:8200"), []byte("server: https://openbao.openbao.svc:8200"))
	if err := writeProfileFile(root, filepath.Join("store", "platform-secrets.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "workload identity contract") {
		t.Fatalf("non-active ClusterSecretStore service was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsDisabledAuthDelegator(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("      authDelegator:\n        enabled: true"), []byte("      authDelegator:\n        enabled: false"))
	if err := writeProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "auth-delegator") {
		t.Fatalf("disabled OpenBao auth delegator was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsBlanketServiceAccountTokenCreation(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("controllers", "releases.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("      serviceAccountTokenCreate: false"), []byte("      serviceAccountTokenCreate: true"))
	if err := writeProfileFile(root, filepath.Join("controllers", "releases.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "blanket service-account token creation") {
		t.Fatalf("blanket service-account token creation was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsExternalSecretsAuthDelegator(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("controllers", "releases.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("    systemAuthDelegator: false"), []byte("    systemAuthDelegator: true"))
	if err := writeProfileFile(root, filepath.Join("controllers", "releases.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "optional privileged surfaces") {
		t.Fatalf("External Secrets auth-delegator permission was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsExternalSecretsExtraObjects(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("controllers", "releases.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("    rbac:\n      serviceAccountTokenCreate: false\n"), []byte(`    rbac:
      serviceAccountTokenCreate: false
    extraObjects:
      - apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRoleBinding
        metadata:
          name: unsafe-controller-access
        roleRef:
          apiGroup: rbac.authorization.k8s.io
          kind: ClusterRole
          name: cluster-admin
        subjects:
          - kind: ServiceAccount
            name: external-secrets
            namespace: external-secrets
`))
	if err := writeProfileFile(root, filepath.Join("controllers", "releases.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "render-time extensions") {
		t.Fatalf("External Secrets extraObjects RBAC injection was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsExternalSecretsPostRenderer(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("controllers", "releases.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("  releaseName: external-secrets\n"), []byte(`  releaseName: external-secrets
  postRenderers:
    - kustomize:
        patches:
          - target:
              kind: ClusterRole
            patch: |-
              - op: add
                path: /rules/-
                value:
                  apiGroups:
                    - "*"
                  resources:
                    - "*"
                  verbs:
                    - "*"
`))
	if err := writeProfileFile(root, filepath.Join("controllers", "releases.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "render-time extensions") {
		t.Fatalf("External Secrets post-rendered RBAC injection was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsExternalSecretsValuesFrom(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("controllers", "releases.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("  releaseName: external-secrets\n"), []byte(`  releaseName: external-secrets
  valuesFrom:
    - kind: ConfigMap
      name: unverified-values
      valuesKey: values.yaml
`))
	if err := writeProfileFile(root, filepath.Join("controllers", "releases.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "render-time extensions") {
		t.Fatalf("External Secrets valuesFrom injection was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsWidenedPlatformTokenRequestRBAC(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("controllers", "token-request-rbac.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("    resourceNames:\n      - external-secrets"), []byte("    resourceNames:\n      - external-secrets\n      - privileged-service"))
	if err := writeProfileFile(root, filepath.Join("controllers", "token-request-rbac.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "platform token-request Role") {
		t.Fatalf("widened platform token-request RBAC was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsConsumerClusterSecretStore(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("kind: SecretStore\nmetadata:\n  name: cloudring-openbao"), []byte("kind: ClusterSecretStore\nmetadata:\n  name: cloudring-openbao"))
	if err := writeProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil {
		t.Fatal("consumer ClusterSecretStore was accepted")
	}
}

func TestSecretManagerProfileRejectsGenericPlatformAuthMount(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("store", "platform-secrets.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("          mountPath: kubernetes-platform-secrets"), []byte("          mountPath: kubernetes"))
	if err := writeProfileFile(root, filepath.Join("store", "platform-secrets.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "platform secret-store workload identity") {
		t.Fatalf("generic platform auth mount was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsGenericConsumerAuthMount(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("          mountPath: kubernetes-consumer-example"), []byte("          mountPath: kubernetes"))
	if err := writeProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "namespaced SecretStore") {
		t.Fatalf("generic consumer auth mount was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsConsumerCrossNamespaceServiceAccount(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("            name: cloudring-openbao-reader\n            audiences:"), []byte("            name: cloudring-openbao-reader\n            namespace: external-secrets\n            audiences:"))
	if err := writeProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "namespaced SecretStore") {
		t.Fatalf("cross-namespace consumer service account was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsConsumerWithoutOpenBaoAudience(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("            audiences:\n              - openbao\n"), nil)
	if err := writeProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "namespaced SecretStore") {
		t.Fatalf("consumer SecretStore without an audience was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsWidenedConsumerTokenRequestRBAC(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("    resourceNames:\n      - cloudring-openbao-reader"), []byte("    resourceNames:\n      - cloudring-openbao-reader\n      - second-reader"))
	if err := writeProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "consumer example token-request Role") {
		t.Fatalf("widened consumer token-request RBAC was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsWrongExternalSecretsRoleBindingSubject(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("subjects:\n  - kind: ServiceAccount\n    name: external-secrets\n    namespace: external-secrets"), []byte("subjects:\n  - kind: ServiceAccount\n    name: openbao\n    namespace: openbao"))
	if err := writeProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "consumer example token-request RoleBinding") {
		t.Fatalf("wrong External Secrets RoleBinding subject was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsConsumerWithoutNonClaim(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("    cloudring.org/non-claim: requires-openbao-policy-role-and-live-sync-proof"), []byte("    cloudring.org/status: source-only"))
	if err := writeProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "namespaced SecretStore") {
		t.Fatalf("consumer SecretStore without a non-claim was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsConsumerTokenAutomount(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("automountServiceAccountToken: false"), []byte("automountServiceAccountToken: true"))
	if err := writeProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "service-account identity") {
		t.Fatalf("consumer service-account token automount was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsConsumerLegacyTokenReference(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("automountServiceAccountToken: false\n"), []byte("automountServiceAccountToken: false\nsecrets:\n  - name: legacy-token\n"))
	if err := writeProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "service-account identity") {
		t.Fatalf("consumer legacy service-account token reference was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsConsumerWithoutTrustLabel(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("    cloudring.org/openbao-client: \"true\"\n"), nil)
	if err := writeProfileFile(root, filepath.Join("consumer-example", "service-store.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "namespace security boundary") {
		t.Fatalf("consumer namespace without the OpenBao trust label was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsUnownedOrUnrestrictedNegativeNamespace(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
	}{
		{
			name:        "ownership label",
			old:         "    cloudring.org/openbao-negative-identity: \"true\"\n",
			replacement: "",
		},
		{
			name:        "restricted policy",
			old:         "    cloudring.org/openbao-negative-identity: \"true\"\n    pod-security.kubernetes.io/enforce: restricted\n",
			replacement: "    cloudring.org/openbao-negative-identity: \"true\"\n    pod-security.kubernetes.io/enforce: baseline\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := copyProfile(t)
			path := filepath.Join("consumer-example", "service-store.yaml")
			data, err := readProfileFile(root, path)
			if err != nil {
				t.Fatal(err)
			}
			data = replaceOnce(t, data, []byte(test.old), []byte(test.replacement))
			if err := writeProfileFile(root, path, data); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "negative namespace security and ownership") {
				t.Fatalf("unsafe negative namespace was accepted: %v", err)
			}
		})
	}
}

func TestSecretManagerProfileRejectsWidenedExternalSecretsIngress(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("runtime", "network-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte(`          podSelector:
            matchLabels:
              app.kubernetes.io/name: external-secrets
              app.kubernetes.io/instance: external-secrets
`), nil)
	if err := writeProfileFile(root, filepath.Join("runtime", "network-policy.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "NetworkPolicy") {
		t.Fatalf("namespace-wide External Secrets ingress was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsOrderedReadyOpenBaoBootstrap(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("      podManagementPolicy: Parallel"), []byte("      podManagementPolicy: OrderedReady"))
	if err := writeProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "TLS HA Raft contract") {
		t.Fatalf("OrderedReady OpenBao bootstrap was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsPodIPHAAddress(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("        apiAddr: https://openbao-active.openbao.svc:8200"), []byte("        apiAddr: https://$(POD_IP):8200"))
	if err := writeProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "TLS HA Raft contract") {
		t.Fatalf("Pod-IP OpenBao HA address was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsReadinessTLSSkipVerify(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte("                    exec bao status\n"), []byte("                    exec bao status -tls-skip-verify\n"))
	if err := writeProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "TLS verification") {
		t.Fatalf("insecure OpenBao readiness probe was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsReadinessWithoutCA(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte(`BAO_CACERT="/openbao/tls/client/ca.crt"`), []byte(`BAO_CACERT=""`))
	if err := writeProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "CA and pod DNS verification") {
		t.Fatalf("OpenBao readiness probe without CA was accepted: %v", err)
	}
}

func TestSecretManagerProfileRejectsReadinessWithoutPodSpecificServerName(t *testing.T) {
	root := copyProfile(t)
	data, err := readProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data = replaceOnce(t, data, []byte(`export BAO_TLS_SERVER_NAME="${pod_dns}"`), []byte(`export BAO_TLS_SERVER_NAME="openbao.openbao.svc"`))
	if err := writeProfileFile(root, filepath.Join("runtime", "openbao-release.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySecretManager(root); err == nil || !strings.Contains(err.Error(), "CA and pod DNS verification") {
		t.Fatalf("OpenBao readiness probe without pod-specific server name was accepted: %v", err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func copyProfile(t *testing.T) string {
	t.Helper()
	source := filepath.Join(repositoryRoot(t), profilePath)
	root := t.TempDir()
	sourceRoot, err := os.OpenRoot(source)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceRoot.Close()
	destination := filepath.Join(root, profilePath)
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	destinationRoot, err := os.OpenRoot(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer destinationRoot.Close()
	for _, relative := range []string{
		"controllers/kustomization.yaml", "controllers/namespaces.yaml", "controllers/releases.yaml", "controllers/repositories.yaml", "controllers/token-request-rbac.yaml",
		"runtime/kustomization.yaml", "runtime/network-policy.yaml", "runtime/openbao-release.yaml", "runtime/tls.yaml",
		"store/kustomization.yaml", "store/platform-secrets.yaml",
		"consumer-example/kustomization.yaml", "consumer-example/service-store.yaml",
		"consumer-example/bootstrap-executor.yaml",
	} {
		data, err := sourceRoot.ReadFile(relative)
		if err != nil {
			t.Fatal(err)
		}
		if err := destinationRoot.MkdirAll(filepath.Dir(relative), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := destinationRoot.WriteFile(relative, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	repository, err := os.OpenRoot(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	profileData, err := repository.ReadFile(bootstrapExecutorProfilePath)
	if err != nil {
		t.Fatal(err)
	}
	destinationRepository, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer destinationRepository.Close()
	if err := destinationRepository.MkdirAll(filepath.Dir(bootstrapExecutorProfilePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := destinationRepository.WriteFile(bootstrapExecutorProfilePath, profileData, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func readProfileFile(root, relative string) ([]byte, error) {
	profile, err := os.OpenRoot(filepath.Join(root, profilePath))
	if err != nil {
		return nil, err
	}
	defer profile.Close()
	return profile.ReadFile(relative)
}

func writeProfileFile(root, relative string, data []byte) error {
	profile, err := os.OpenRoot(filepath.Join(root, profilePath))
	if err != nil {
		return err
	}
	defer profile.Close()
	return profile.WriteFile(relative, data, 0o600)
}

func replaceOnce(t *testing.T, data, old, replacement []byte) []byte {
	t.Helper()
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	position := -1
	for index := 0; index+len(old) <= len(data); index++ {
		match := true
		for offset := range old {
			if data[index+offset] != old[offset] {
				match = false
				break
			}
		}
		if match {
			position = index
			break
		}
	}
	if position < 0 {
		t.Fatal("fixture token not found")
	}
	result := make([]byte, 0, len(data)-len(old)+len(replacement))
	result = append(result, data[:position]...)
	result = append(result, replacement...)
	result = append(result, data[position+len(old):]...)
	return result
}

const persistentAuditHCL = `            audit "file" "persistent" {
              description = "CloudRING persistent audit"
              options {
                file_path = "/openbao/audit/audit.log"
                mode      = "0600"
                log_raw   = "false"
              }
            }

`
