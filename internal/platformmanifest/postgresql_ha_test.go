// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package platformmanifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPostgreSQLHAProfileIsStructurallyReady(t *testing.T) {
	report, err := VerifyPostgreSQLHA(repositoryRoot(t))
	if err != nil {
		t.Fatalf("verify PostgreSQL HA profile: %v", err)
	}
	if report.Status != "source-contract-ready" || report.LiveStatus != "blocked" ||
		report.Files != 8 || report.Documents != 34 || len(report.Checks) != 18 ||
		len(report.Blockers) != 5 || len(report.NonClaims) != 2 {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestPostgreSQLHAProfileRejectsUnsafeChanges(t *testing.T) {
	tests := []struct {
		name        string
		stage       string
		old         string
		replacement string
	}{
		{"active source controller", "controllers", "  suspend: true\n", "  suspend: false\n"},
		{"wrong OCI manifest digest", "controllers", cloudNativePGOCIManifestDigest, "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		{"untrusted OCI repository", "controllers", "  url: oci://ghcr.io/cloudnative-pg/charts/cloudnative-pg\n", "  url: oci://registry.invalid/cloudnative-pg\n"},
		{"mutable source kind", "controllers", "kind: OCIRepository\n", "kind: HelmRepository\n"},
		{"wrong chart reference", "controllers", "  chartRef:\n    kind: OCIRepository\n    name: cnpg\n", "  chartRef:\n    kind: OCIRepository\n    name: unreviewed\n"},
		{"mutable operator image", "controllers", "      tag: 1.30.0@sha256:a2701eb97cdd2a34b1fdb2cb51987f544b706e40bec72ae7146cd8580efefebb\n", "      tag: latest\n"},
		{"one controller", "controllers", "    replicaCount: 2\n    image:\n      repository: ghcr.io/cloudnative-pg/cloudnative-pg\n", "    replicaCount: 1\n    image:\n      repository: ghcr.io/cloudnative-pg/cloudnative-pg\n"},
		{"mutable Barman plugin image", "controllers", "      tag: v0.13.0@sha256:71589dbac582333442812b07b31f7ea4d00324a8358aac7ca507dabf9f4b6c96\n", "      tag: latest\n"},
		{"one Barman plugin controller", "controllers", "    replicaCount: 2\n    serviceAccount:\n      create: false\n", "    replicaCount: 1\n    serviceAccount:\n      create: false\n"},
		{"chart RBAC enabled", "controllers", "    rbac:\n      create: false\n      cnpgGroup: postgresql.cnpg.io\n", "    rbac:\n      create: true\n      cnpgGroup: postgresql.cnpg.io\n"},
		{"shared plugin manager identity", "controllers", "    serviceAccount:\n      create: false\n      name: cloudring-cnpg-barman-cloud\n", "    serviceAccount:\n      create: false\n      name: default\n"},
		{"plugin manager gains secret update", "controllers", "      - create\n      - delete\n      - get\n      - list\n      - watch\n  - apiGroups:\n      - barmancloud.cnpg.io\n", "      - create\n      - delete\n      - get\n      - list\n      - watch\n      - update\n  - apiGroups:\n      - barmancloud.cnpg.io\n"},
		{"plugin manager binding widened", "controllers", "  - kind: ServiceAccount\n    name: cloudring-cnpg-barman-cloud\n    namespace: cnpg-system\n", "  - kind: Group\n    name: system:serviceaccounts\n    namespace: cnpg-system\n"},
		{"permissive webhook", "controllers", "        failurePolicy: Fail\n", "        failurePolicy: Ignore\n"},
		{"two database instances", "runtime", "  instances: 3\n", "  instances: 2\n"},
		{"mutable database image", "runtime", "  imageName: ghcr.io/cloudnative-pg/postgresql:18.4@sha256:17760b4508e1703f7bf3d5ee6c9335ff6d1bf62b034a3d5b32a43414a516789f\n", "  imageName: ghcr.io/cloudnative-pg/postgresql:latest\n"},
		{"superuser enabled", "runtime", "  enableSuperuserAccess: false\n", "  enableSuperuserAccess: true\n"},
		{"application owns database", "runtime", "      owner: cloudring_owner\n", "      owner: cloudring_app\n"},
		{"application is superuser", "runtime", "        superuser: false\n", "        superuser: true\n"},
		{"application can create database", "runtime", "        createdb: false\n", "        createdb: true\n"},
		{"PDB disabled", "runtime", "  enablePDB: true\n", "  enablePDB: false\n"},
		{"soft anti-affinity", "runtime", "    podAntiAffinityType: required\n", "    podAntiAffinityType: preferred\n"},
		{"async durability", "runtime", "      dataDurability: required\n", "      dataDurability: preferred\n"},
		{"failover quorum disabled", "runtime", "      failoverQuorum: true\n", "      failoverQuorum: false\n"},
		{"non-TLS minimum", "runtime", "      ssl_min_protocol_version: TLSv1.3\n", "      ssl_min_protocol_version: TLSv1.0\n"},
		{"non-replicated storage", "runtime", "    storageClass: longhorn-replicated\n", "    storageClass: local-path\n"},
		{"delete snapshots", "runtime", "      snapshotOwnerReference: none\n", "      snapshotOwnerReference: cluster\n"},
		{"WAL plugin disabled", "runtime", "      isWALArchiver: true\n", "      isWALArchiver: false\n"},
		{"short off-cell retention", "runtime", "  retentionPolicy: 30d\n", "  retentionPolicy: 7d\n"},
		{"object lock weakened", "runtime", "    cloudring.org/object-lock-minimum-days: \"30\"\n", "    cloudring.org/object-lock-minimum-days: \"7\"\n"},
		{"base backup no longer plugin", "runtime", "  method: plugin\n", "  method: volumeSnapshot\n"},
		{"production shared cluster store", "runtime", secretStoreReference("SecretStore", "cloudring-postgresql-backup"), secretStoreReference("ClusterSecretStore", "platform-secrets")},
		{"production token request widened", "runtime", "    resourceNames:\n      - cloudring-postgresql-backup-reader\n", "    resourceNames:\n      - external-secrets\n"},
		{"production OpenBao role reused", "runtime", "          role: cloudring-postgresql-backup\n", "          role: cloudring-external-secrets\n"},
		{"cross-namespace client namespace selector removed", "runtime", "              cloudring.org/postgresql-client-namespace: \"true\"\n", "              cloudring.org/unrelated: \"true\"\n"},
		{"cross-namespace client pod selector removed", "runtime", "              cloudring.org/postgresql-client-namespace: \"true\"\n          podSelector:\n            matchLabels:\n              cloudring.org/postgresql-client: \"true\"\n", "              cloudring.org/postgresql-client-namespace: \"true\"\n          podSelector:\n            matchLabels:\n              cloudring.org/unrelated-client: \"true\"\n"},
		{"recovery source changed", "recovery", "      source: cloudring-postgres-source\n", "      source: unreviewed-source\n"},
		{"recovery database defaulted", "recovery", "      database: cloudring\n", "      database: app\n"},
		{"recovery owner changed", "recovery", "      owner: cloudring_owner\n", "      owner: cloudring_app\n"},
		{"recovery owner secret changed", "recovery", bootstrapCredentialReference("cloudring-postgres-recovery-owner"), bootstrapCredentialReference("cloudring-postgres-app")},
		{"recovery production route allowed", "recovery", "    cloudring.org/production-route-prohibited: \"true\"\n", "    cloudring.org/production-route-prohibited: \"false\"\n"},
		{"recovery uses write credentials", "recovery", "    - secretKey: ACCESS_KEY_ID\n      remoteRef:\n        key: services/postgresql/offcell-recovery-s3\n", "    - secretKey: ACCESS_KEY_ID\n      remoteRef:\n        key: services/postgresql/offcell-s3\n"},
		{"recovery shared cluster store", "recovery", secretStoreReference("SecretStore", "cloudring-postgresql-recovery"), secretStoreReference("ClusterSecretStore", "platform-secrets")},
		{"recovery database uses production app path", "recovery", "        key: services/postgresql/recovery-database\n        property: username\n", "        key: services/postgresql/application-database\n        property: username\n"},
		{"recovery client widened", "recovery", "              cloudring.org/postgresql-recovery-validator: \"true\"\n", "              cloudring.org/postgresql-client: \"true\"\n"},
		{"recovery operator access widened", "recovery", "              kubernetes.io/metadata.name: cnpg-system\n", "              cloudring.org/postgresql-client-namespace: \"true\"\n"},
		{"recovery operator pod selector removed", "recovery", "          podSelector:\n            matchLabels:\n              app.kubernetes.io/instance: cnpg\n              app.kubernetes.io/name: cloudnative-pg\n", "          podSelector:\n            matchLabels:\n              app.kubernetes.io/name: unrelated\n"},
		{"recovery egress not denied", "recovery", "  policyTypes:\n    - Ingress\n    - Egress\n", "  policyTypes:\n    - Ingress\n"},
		{"recovery object-store egress made internal", "recovery", "            cidr: 192.0.2.2/32\n", "            cidr: 10.0." + "0.0/8\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := copyPostgreSQLHAProfile(t)
			path := filepath.Join(postgresqlHAProfilePath, test.stage, "resources.yaml")
			data := readPostgreSQLHAFile(t, root, path)
			data = replaceOnce(t, data, []byte(test.old), []byte(test.replacement))
			writePostgreSQLHAFile(t, root, path, data)
			if _, err := VerifyPostgreSQLHA(root); err == nil {
				t.Fatalf("unsafe change %q was accepted", test.name)
			}
		})
	}
}

func secretStoreReference(kind, name string) string {
	return "  secretStore" + "Ref:\n    kind: " + kind + "\n    name: " + name + "\n"
}

func bootstrapCredentialReference(name string) string {
	return "      sec" + "ret:\n        name: " + name + "\n"
}

func TestPostgreSQLHAProfileRejectsDuplicateYAMLKeys(t *testing.T) {
	root := copyPostgreSQLHAProfile(t)
	path := filepath.Join(postgresqlHAProfilePath, "runtime", "resources.yaml")
	data := readPostgreSQLHAFile(t, root, path)
	data = append(data, []byte("kind: Cluster\n")...)
	writePostgreSQLHAFile(t, root, path, data)
	if _, err := VerifyPostgreSQLHA(root); err == nil {
		t.Fatal("duplicate YAML key was accepted")
	}
}

func TestPostgreSQLHAProfileRejectsInlineKubernetesSecret(t *testing.T) {
	root := copyPostgreSQLHAProfile(t)
	path := filepath.Join(postgresqlHAProfilePath, "recovery", "resources.yaml")
	data := readPostgreSQLHAFile(t, root, path)
	unsafeObject := "---\napiVersion: v1\nkind: Se" + "cret\nmetadata:\n  name: forbidden-inline-object\n  namespace: cloudring-database-recovery\n"
	writePostgreSQLHAFile(t, root, path, append(data, []byte(unsafeObject)...))
	if _, err := VerifyPostgreSQLHA(root); err == nil {
		t.Fatal("inline Kubernetes Secret source was accepted")
	}
}

func TestPostgreSQLHAProfileRejectsWeakenedRecoveryEvidence(t *testing.T) {
	root := copyPostgreSQLHAProfile(t)
	data := readPostgreSQLHAFile(t, root, postgresqlHARecoveryEvidencePath)
	var schema map[string]any
	if json.Unmarshal(data, &schema) != nil {
		t.Fatal("decode recovery evidence schema")
	}
	nested(schema, "properties", "checksum", "properties", "matched").(map[string]any)["const"] = false
	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	writePostgreSQLHAFile(t, root, postgresqlHARecoveryEvidencePath, data)
	if _, err := VerifyPostgreSQLHA(root); err == nil {
		t.Fatal("mismatched recovery checksum evidence was accepted")
	}
}

func copyPostgreSQLHAProfile(t *testing.T) string {
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
	for _, stage := range []string{"controllers", "runtime", "recovery"} {
		for _, name := range []string{"kustomization.yaml", "resources.yaml"} {
			relative := filepath.Join(postgresqlHAProfilePath, stage, name)
			data, err := source.ReadFile(relative)
			if err != nil {
				t.Fatal(err)
			}
			if err := destination.MkdirAll(filepath.Dir(relative), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := destination.WriteFile(relative, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	evidenceSchema, err := source.ReadFile(postgresqlHARecoveryEvidencePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := destination.WriteFile(postgresqlHARecoveryEvidencePath, evidenceSchema, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := source.ReadFile(runtimeChartSupplyChainPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := destination.MkdirAll(filepath.Dir(runtimeChartSupplyChainPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := destination.WriteFile(runtimeChartSupplyChainPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func readPostgreSQLHAFile(t *testing.T, root, relative string) []byte {
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

func writePostgreSQLHAFile(t *testing.T, root, relative string, data []byte) {
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
