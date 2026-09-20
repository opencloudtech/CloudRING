// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

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
	postgresqlHAProfilePath              = "deploy/kubernetes/postgresql-ha"
	postgresqlHARecoveryEvidencePath     = postgresqlHAProfilePath + "/recovery/evidence.schema.json"
	cloudNativePGOCIManifestDigest       = "sha256:209c588b902982bf283a0073db83edd422d9710a2c8a670fe57c0329abe789a4"
	cloudNativePGBarmanOCIManifestDigest = "sha256:5d31605cad886f93abb7cd9884170d74ece913fe8b95c74b127ec5e8bcd2b2b6"
)

// VerifyPostgreSQLHA validates the reusable HA database source contract. It
// deliberately does not turn structural checks into a live durability claim.
func VerifyPostgreSQLHA(root string) (Report, error) {
	root, err := canonicalRoot(root)
	if err != nil {
		return Report{}, err
	}
	report := Report{Status: "blocked", Profile: "cloudring-postgresql-ha/v1"}
	repository, err := os.OpenRoot(root)
	if err != nil {
		return report, errors.New("open confined repository root")
	}
	defer repository.Close()
	artifact, err := requireRuntimeChartArtifact(repository, "cloudnative-pg")
	if err != nil || artifact.ManifestDigest != cloudNativePGOCIManifestDigest || artifact.AppVersion != "1.30.0" {
		return report, errors.New("CloudNativePG reviewed OCI artifact contract is invalid")
	}
	barmanArtifact, err := requireRuntimeChartArtifact(repository, "cloudnative-pg-barman-cloud")
	if err != nil || barmanArtifact.ManifestDigest != cloudNativePGBarmanOCIManifestDigest ||
		barmanArtifact.Version != "0.7.0" || barmanArtifact.AppVersion != "v0.13.0" || len(barmanArtifact.Images) != 2 {
		return report, errors.New("Barman Cloud Plugin reviewed OCI artifact contract is invalid")
	}

	var objects []object
	for _, stage := range []string{"controllers", "runtime", "recovery"} {
		stageObjects, files, readErr := readPostgreSQLHAStage(repository, stage)
		if readErr != nil {
			return report, readErr
		}
		report.Files += files
		objects = append(objects, stageObjects...)
	}
	// Count the shared supply-chain manifest consumed above as a verifier input.
	report.Files++
	evidenceSchema, err := readRegular(repository, postgresqlHARecoveryEvidencePath)
	if err != nil || validatePostgreSQLHARecoveryEvidenceSchema(evidenceSchema) != nil {
		return report, errors.New("PostgreSQL recovery evidence schema is invalid")
	}
	report.Files++
	report.Documents = len(objects)
	if report.Files != 8 || report.Documents != 34 {
		return report, errors.New("PostgreSQL HA source inventory is incomplete")
	}
	index, err := exactPostgreSQLHAInventory(objects)
	if err != nil {
		return report, err
	}
	if err := validatePostgreSQLHAControllers(index); err != nil {
		return report, err
	}
	if err := validatePostgreSQLHARuntime(index); err != nil {
		return report, err
	}
	if err := validatePostgreSQLHARecovery(index); err != nil {
		return report, err
	}
	report.Status = "source-contract-ready"
	report.LiveStatus = "blocked"
	report.Checks = []string{
		"source_controller_suspended",
		"controller_oci_chart_and_image_digest_pinned",
		"admission_webhook_source_policy_fail_closed",
		"controller_replica_and_disruption_budget_source_contract",
		"three_postgresql_instances_and_hard_host_separation_declared",
		"quorum_synchronous_durability_declared",
		"tls_scram_and_application_role_source_contract",
		"replicated_pgdata_and_wal_source_contract",
		"retained_online_snapshot_schedule_source_contract",
		"barman_cloud_plugin_chart_and_images_digest_pinned",
		"barman_cloud_chart_rbac_disabled_and_exact_upstream_manager_rbac_declared",
		"continuous_off_cell_wal_and_scheduled_base_backup_source_contract",
		"thirty_day_retention_and_object_lock_site_contract_declared",
		"namespaced_external_secret_identities_source_contract",
		"isolated_recovery_source_profile_verified",
		"recovery_network_site_bindings_fail_closed",
		"recovery_checksum_readiness_cleanup_schema_and_instance_verifier_present",
		"live_wal_backup_recovery_cleanup_and_failover_blocked",
	}
	report.Blockers = []string{
		"private Kubernetes API and dedicated off-cell object-store egress bindings are not supplied",
		"namespaced OpenBao auth roles CA projection secret synchronization rotation and revocation are not live-proven",
		"plugin TLS reconciliation continuous WAL and scheduled base backup are not live-proven",
		"off-cell failure-domain retention Object Lock and denied control deletion are not live-proven",
		"no isolated recovery evidence instance has passed checksum readiness chronology and two-sweep cleanup verification",
	}
	report.NonClaims = []string{
		"source manifests and immutable digests do not establish live durability or recoverability",
		"plugin-barman-cloud v0.13.0 requires its exact upstream cluster-wide manager RBAC because it has no namespace watch restriction",
	}
	return report, nil
}

func readPostgreSQLHAStage(root *os.Root, stage string) ([]object, int, error) {
	directory := filepath.Join(postgresqlHAProfilePath, stage)
	kustomization, err := readRegular(root, filepath.Join(directory, "kustomization.yaml"))
	if err != nil {
		return nil, 0, err
	}
	var manifest map[string]any
	if err := decodeOne(kustomization, &manifest); err != nil ||
		!exactMappingKeys(manifest, "apiVersion", "kind", "resources") ||
		nestedString(manifest, "apiVersion") != "kustomize.config.k8s.io/v1beta1" ||
		nestedString(manifest, "kind") != "Kustomization" ||
		!exactStringSequence(manifest["resources"], "resources.yaml") {
		return nil, 0, fmt.Errorf("PostgreSQL HA %s stage has an invalid kustomization", stage)
	}
	data, err := readRegular(root, filepath.Join(directory, "resources.yaml"))
	if err != nil {
		return nil, 0, err
	}
	for _, forbidden := range [][]byte{
		[]byte(":latest"), []byte("REPLACE_WITH"), []byte("example.invalid"),
		[]byte("kind: Secret\n"), []byte("postgres://"), []byte("sslmode=disable"),
	} {
		if bytes.Contains(data, forbidden) {
			return nil, 0, errors.New("PostgreSQL HA source contains mutable, unresolved, or secret material")
		}
	}
	objects, err := decodeObjects(data)
	if err != nil {
		return nil, 0, fmt.Errorf("decode PostgreSQL HA %s stage: %w", stage, err)
	}
	return objects, 2, nil
}

func exactPostgreSQLHAInventory(objects []object) (map[string]object, error) {
	index := make(map[string]object, len(objects))
	for _, item := range objects {
		key := item.Kind + "/" + item.Namespace + "/" + item.Name
		if _, duplicate := index[key]; duplicate {
			return nil, errors.New("duplicate PostgreSQL HA manifest object identity")
		}
		index[key] = item
	}
	expected := []string{
		"Cluster/cloudring-database-recovery/cloudring-postgres-recovery",
		"Cluster/cloudring-database/cloudring-postgres",
		"ClusterRole//cloudring-cnpg-barman-cloud-upstream-v0130",
		"ClusterRoleBinding//cloudring-cnpg-barman-cloud-upstream-v0130",
		"ExternalSecret/cloudring-database-recovery/cloudring-postgres-offcell-recovery-s3",
		"ExternalSecret/cloudring-database-recovery/cloudring-postgres-recovery-database",
		"ExternalSecret/cloudring-database/cloudring-postgres-offcell-s3",
		"HelmRelease/cnpg-system/cnpg",
		"HelmRelease/cnpg-system/cnpg-barman-cloud",
		"Namespace//cloudring-database-recovery",
		"Namespace//cloudring-database",
		"Namespace//cnpg-system",
		"NetworkPolicy/cloudring-database-recovery/cloudring-postgres-recovery-isolation",
		"NetworkPolicy/cloudring-database-recovery/cloudring-postgres-recovery-kubernetes-api-egress-binding",
		"NetworkPolicy/cloudring-database-recovery/cloudring-postgres-recovery-object-store-egress-binding",
		"NetworkPolicy/cloudring-database/cloudring-postgres-ingress",
		"OCIRepository/cnpg-system/cnpg",
		"OCIRepository/cnpg-system/cnpg-barman-cloud",
		"ObjectStore/cloudring-database-recovery/cloudring-postgres-offcell-recovery",
		"ObjectStore/cloudring-database/cloudring-postgres-offcell",
		"PodDisruptionBudget/cnpg-system/cnpg-barman-cloud",
		"PodDisruptionBudget/cnpg-system/cnpg-controller-manager",
		"Role/cloudring-database-recovery/cloudring-postgresql-recovery-token-request",
		"Role/cloudring-database/cloudring-postgresql-backup-token-request",
		"RoleBinding/cloudring-database-recovery/cloudring-postgresql-recovery-token-request",
		"RoleBinding/cloudring-database/cloudring-postgresql-backup-token-request",
		"ScheduledBackup/cloudring-database/cloudring-postgres-offcell",
		"ScheduledBackup/cloudring-database/cloudring-postgres-volume-snapshot",
		"SecretStore/cloudring-database-recovery/cloudring-postgresql-recovery",
		"SecretStore/cloudring-database/cloudring-postgresql-backup",
		"ServiceAccount/cloudring-database-recovery/cloudring-postgres-recovery-validator",
		"ServiceAccount/cloudring-database-recovery/cloudring-postgresql-recovery-reader",
		"ServiceAccount/cloudring-database/cloudring-postgresql-backup-reader",
		"ServiceAccount/cnpg-system/cloudring-cnpg-barman-cloud",
	}
	sort.Strings(expected)
	actual := make([]string, 0, len(index))
	for key := range index {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		return nil, errors.New("PostgreSQL HA object inventory is not exact")
	}
	return index, nil
}

func validatePostgreSQLHAControllers(index map[string]object) error {
	repository := index["OCIRepository/cnpg-system/cnpg"].Data
	if nestedString(repository, "apiVersion") != "source.toolkit.fluxcd.io/v1" ||
		!exactMappingKeys(nested(repository, "spec"), "interval", "url", "ref", "layerSelector") ||
		nestedString(repository, "spec", "url") != "oci://ghcr.io/cloudnative-pg/charts/cloudnative-pg" ||
		nestedString(repository, "spec", "interval") != "1h" ||
		!exactMappingKeys(nested(repository, "spec", "ref"), "digest") ||
		nestedString(repository, "spec", "ref", "digest") != cloudNativePGOCIManifestDigest ||
		!exactMappingKeys(nested(repository, "spec", "layerSelector"), "mediaType", "operation") ||
		nestedString(repository, "spec", "layerSelector", "mediaType") != "application/vnd.cncf.helm.chart.content.v1.tar+gzip" ||
		nestedString(repository, "spec", "layerSelector", "operation") != "copy" {
		return errors.New("CloudNativePG OCI chart source is invalid")
	}
	release := index["HelmRelease/cnpg-system/cnpg"].Data
	if !exactMappingKeys(nested(release, "spec"), "suspend", "interval", "timeout", "releaseName", "chartRef", "install", "upgrade", "values") ||
		!exactBool(release, true, "spec", "suspend") ||
		nestedString(release, "spec", "interval") != "15m" ||
		nestedString(release, "spec", "timeout") != "10m" ||
		nestedString(release, "spec", "releaseName") != "cnpg" ||
		!exactMappingKeys(nested(release, "spec", "chartRef"), "kind", "name", "namespace") ||
		nestedString(release, "spec", "chartRef", "kind") != "OCIRepository" ||
		nestedString(release, "spec", "chartRef", "name") != "cnpg" ||
		nestedString(release, "spec", "chartRef", "namespace") != "cnpg-system" ||
		nestedString(release, "metadata", "annotations", "cloudring.org/non-claim") == "" {
		return errors.New("CloudNativePG release boundary is invalid")
	}
	if nestedNumber(release, "spec", "values", "replicaCount") != 2 ||
		nestedString(release, "spec", "values", "image", "repository") != "ghcr.io/cloudnative-pg/cloudnative-pg" ||
		nestedString(release, "spec", "values", "image", "tag") != "1.30.0@sha256:a2701eb97cdd2a34b1fdb2cb51987f544b706e40bec72ae7146cd8580efefebb" ||
		!exactBool(release, true, "spec", "values", "crds", "create") ||
		nestedString(release, "spec", "values", "webhook", "mutating", "failurePolicy") != "Fail" ||
		nestedString(release, "spec", "values", "webhook", "validating", "failurePolicy") != "Fail" ||
		!exactBool(release, true, "spec", "values", "config", "clusterWide") ||
		!exactBool(release, false, "spec", "values", "rbac", "aggregateClusterRoles") ||
		!exactBool(release, false, "spec", "values", "containerSecurityContext", "allowPrivilegeEscalation") ||
		!exactBool(release, true, "spec", "values", "containerSecurityContext", "readOnlyRootFilesystem") {
		return errors.New("CloudNativePG controller values are invalid")
	}
	spreads, ok := nested(release, "spec", "values", "topologySpreadConstraints").([]any)
	if !ok || len(spreads) != 1 {
		return errors.New("CloudNativePG controller topology is invalid")
	}
	spread, ok := spreads[0].(map[string]any)
	if !ok || nestedNumber(spread, "maxSkew") != 1 || nestedString(spread, "topologyKey") != "kubernetes.io/hostname" || nestedString(spread, "whenUnsatisfiable") != "DoNotSchedule" {
		return errors.New("CloudNativePG controller topology is invalid")
	}
	budget := index["PodDisruptionBudget/cnpg-system/cnpg-controller-manager"].Data
	if nestedNumber(budget, "spec", "minAvailable") != 1 ||
		nestedString(budget, "spec", "selector", "matchLabels", "app.kubernetes.io/instance") != "cnpg" ||
		nestedString(budget, "spec", "selector", "matchLabels", "app.kubernetes.io/name") != "cloudnative-pg" {
		return errors.New("CloudNativePG controller disruption budget is invalid")
	}
	barmanRepository := index["OCIRepository/cnpg-system/cnpg-barman-cloud"].Data
	if nestedString(barmanRepository, "apiVersion") != "source.toolkit.fluxcd.io/v1" ||
		!exactMappingKeys(nested(barmanRepository, "spec"), "interval", "url", "ref", "layerSelector") ||
		nestedString(barmanRepository, "spec", "url") != "oci://ghcr.io/cloudnative-pg/charts/plugin-barman-cloud" ||
		nestedString(barmanRepository, "spec", "interval") != "1h" ||
		!exactMappingKeys(nested(barmanRepository, "spec", "ref"), "digest") ||
		nestedString(barmanRepository, "spec", "ref", "digest") != cloudNativePGBarmanOCIManifestDigest ||
		nestedString(barmanRepository, "spec", "layerSelector", "mediaType") != "application/vnd.cncf.helm.chart.content.v1.tar+gzip" ||
		nestedString(barmanRepository, "spec", "layerSelector", "operation") != "copy" {
		return errors.New("Barman Cloud Plugin OCI chart source is invalid")
	}
	barmanRelease := index["HelmRelease/cnpg-system/cnpg-barman-cloud"].Data
	if !exactMappingKeys(nested(barmanRelease, "spec"), "suspend", "interval", "timeout", "releaseName", "chartRef", "install", "upgrade", "values") ||
		!exactBool(barmanRelease, true, "spec", "suspend") ||
		nestedString(barmanRelease, "spec", "interval") != "15m" ||
		nestedString(barmanRelease, "spec", "timeout") != "10m" ||
		nestedString(barmanRelease, "spec", "releaseName") != "plugin-barman-cloud" ||
		nestedString(barmanRelease, "spec", "chartRef", "kind") != "OCIRepository" ||
		nestedString(barmanRelease, "spec", "chartRef", "name") != "cnpg-barman-cloud" ||
		nestedString(barmanRelease, "spec", "chartRef", "namespace") != "cnpg-system" ||
		nestedString(barmanRelease, "metadata", "annotations", "cloudring.org/non-claim") == "" {
		return errors.New("Barman Cloud Plugin release boundary is invalid")
	}
	if nestedNumber(barmanRelease, "spec", "values", "replicaCount") != 2 ||
		!exactBool(barmanRelease, false, "spec", "values", "serviceAccount", "create") ||
		nestedString(barmanRelease, "spec", "values", "serviceAccount", "name") != "cloudring-cnpg-barman-cloud" ||
		!exactBool(barmanRelease, false, "spec", "values", "rbac", "create") ||
		nestedString(barmanRelease, "spec", "values", "rbac", "cnpgGroup") != "postgresql.cnpg.io" ||
		nestedString(barmanRelease, "spec", "values", "image", "registry") != "ghcr.io" ||
		nestedString(barmanRelease, "spec", "values", "image", "repository") != "cloudnative-pg/plugin-barman-cloud" ||
		nestedString(barmanRelease, "spec", "values", "image", "tag") != "v0.13.0@sha256:71589dbac582333442812b07b31f7ea4d00324a8358aac7ca507dabf9f4b6c96" ||
		nestedString(barmanRelease, "spec", "values", "sidecarImage", "registry") != "ghcr.io" ||
		nestedString(barmanRelease, "spec", "values", "sidecarImage", "repository") != "cloudnative-pg/plugin-barman-cloud-sidecar" ||
		nestedString(barmanRelease, "spec", "values", "sidecarImage", "tag") != "v0.13.0@sha256:990361af3319f9e23aafa0f6d7981f99bf1f69b4e6a85cf1bc7d71d6f09bb288" ||
		!exactBool(barmanRelease, true, "spec", "values", "crds", "create") ||
		!exactBool(barmanRelease, false, "spec", "values", "containerSecurityContext", "allowPrivilegeEscalation") ||
		!exactBool(barmanRelease, true, "spec", "values", "containerSecurityContext", "readOnlyRootFilesystem") ||
		nestedString(barmanRelease, "spec", "values", "service", "ipFamilyPolicy") != "PreferDualStack" ||
		!exactBool(barmanRelease, true, "spec", "values", "certificate", "createClientCertificate") ||
		!exactBool(barmanRelease, true, "spec", "values", "certificate", "createServerCertificate") ||
		!exactBool(barmanRelease, true, "spec", "values", "certificate", "createIssuer") {
		return errors.New("Barman Cloud Plugin values are invalid")
	}
	barmanSpreads, ok := nested(barmanRelease, "spec", "values", "topologySpreadConstraints").([]any)
	if !ok || len(barmanSpreads) != 1 {
		return errors.New("Barman Cloud Plugin topology is invalid")
	}
	barmanSpread, ok := barmanSpreads[0].(map[string]any)
	if !ok || nestedNumber(barmanSpread, "maxSkew") != 1 ||
		nestedString(barmanSpread, "topologyKey") != "kubernetes.io/hostname" ||
		nestedString(barmanSpread, "whenUnsatisfiable") != "DoNotSchedule" ||
		nestedString(barmanSpread, "labelSelector", "matchLabels", "app.kubernetes.io/instance") != "plugin-barman-cloud" ||
		nestedString(barmanSpread, "labelSelector", "matchLabels", "app.kubernetes.io/name") != "plugin-barman-cloud" {
		return errors.New("Barman Cloud Plugin topology is invalid")
	}
	barmanServiceAccount := index["ServiceAccount/cnpg-system/cloudring-cnpg-barman-cloud"].Data
	if !exactBool(barmanServiceAccount, true, "automountServiceAccountToken") ||
		nestedString(barmanServiceAccount, "metadata", "annotations", "cloudring.org/rbac-source") != "plugin-barman-cloud-v0.13.0" {
		return errors.New("Barman Cloud Plugin service account is invalid")
	}
	barmanRole := index["ClusterRole//cloudring-cnpg-barman-cloud-upstream-v0130"].Data
	if nestedString(barmanRole, "metadata", "annotations", "cloudring.org/upstream-chart-source-sha") != "83bd9c59514cb7ff3692049d85ba604dcb458700" ||
		nestedString(barmanRole, "metadata", "annotations", "cloudring.org/upstream-plugin-source-sha") != "1cd26c92867bd27a8cc14beab8e455cf3b64cb10" ||
		nestedString(barmanRole, "metadata", "annotations", "cloudring.org/non-claim") == "" ||
		!exactPostgreSQLBarmanManagerRules(nested(barmanRole, "rules")) {
		return errors.New("Barman Cloud Plugin reviewed upstream RBAC is invalid")
	}
	barmanRoleBinding := index["ClusterRoleBinding//cloudring-cnpg-barman-cloud-upstream-v0130"].Data
	if nestedString(barmanRoleBinding, "metadata", "annotations", "cloudring.org/non-claim") == "" ||
		nestedString(barmanRoleBinding, "roleRef", "apiGroup") != "rbac.authorization.k8s.io" ||
		nestedString(barmanRoleBinding, "roleRef", "kind") != "ClusterRole" ||
		nestedString(barmanRoleBinding, "roleRef", "name") != "cloudring-cnpg-barman-cloud-upstream-v0130" ||
		!exactPostgreSQLServiceAccountSubject(nested(barmanRoleBinding, "subjects"), "cloudring-cnpg-barman-cloud", "cnpg-system") {
		return errors.New("Barman Cloud Plugin reviewed upstream RBAC binding is invalid")
	}
	barmanBudget := index["PodDisruptionBudget/cnpg-system/cnpg-barman-cloud"].Data
	if nestedNumber(barmanBudget, "spec", "minAvailable") != 1 ||
		nestedString(barmanBudget, "spec", "selector", "matchLabels", "app.kubernetes.io/instance") != "plugin-barman-cloud" ||
		nestedString(barmanBudget, "spec", "selector", "matchLabels", "app.kubernetes.io/name") != "plugin-barman-cloud" {
		return errors.New("Barman Cloud Plugin disruption budget is invalid")
	}
	return nil
}

func exactPostgreSQLBarmanManagerRules(value any) bool {
	rules, ok := value.([]any)
	if !ok || len(rules) != 7 {
		return false
	}
	return exactPostgreSQLRBACRule(rules[0], []string{""}, []string{"secrets"}, []string{"create", "delete", "get", "list", "watch"}) &&
		exactPostgreSQLRBACRule(rules[1], []string{"barmancloud.cnpg.io"}, []string{"objectstores"}, []string{"create", "delete", "get", "list", "patch", "update", "watch"}) &&
		exactPostgreSQLRBACRule(rules[2], []string{"barmancloud.cnpg.io"}, []string{"objectstores/finalizers"}, []string{"update"}) &&
		exactPostgreSQLRBACRule(rules[3], []string{"barmancloud.cnpg.io"}, []string{"objectstores/status"}, []string{"get", "patch", "update"}) &&
		exactPostgreSQLRBACRule(rules[4], []string{"postgresql.cnpg.io"}, []string{"backups"}, []string{"get", "list", "watch"}) &&
		exactPostgreSQLRBACRule(rules[5], []string{"postgresql.cnpg.io"}, []string{"clusters/finalizers"}, []string{"update"}) &&
		exactPostgreSQLRBACRule(rules[6], []string{"rbac.authorization.k8s.io"}, []string{"rolebindings", "roles"}, []string{"create", "get", "list", "patch", "update", "watch"})
}

func exactPostgreSQLRBACRule(value any, apiGroups, resources, verbs []string) bool {
	rule, ok := value.(map[string]any)
	return ok && exactMappingKeys(rule, "apiGroups", "resources", "verbs") &&
		exactStringSequence(rule["apiGroups"], apiGroups...) &&
		exactStringSequence(rule["resources"], resources...) &&
		exactStringSequence(rule["verbs"], verbs...)
}

func exactPostgreSQLServiceAccountSubject(value any, name, namespace string) bool {
	subjects, ok := value.([]any)
	if !ok || len(subjects) != 1 {
		return false
	}
	subject, ok := subjects[0].(map[string]any)
	return ok && exactMappingKeys(subject, "kind", "name", "namespace") &&
		nestedString(subject, "kind") == "ServiceAccount" &&
		nestedString(subject, "name") == name && nestedString(subject, "namespace") == namespace
}

func validatePostgreSQLHARuntime(index map[string]object) error {
	if nestedString(index["Namespace//cloudring-database"].Data, "metadata", "labels", "cloudring.org/openbao-client") != "true" ||
		!exactPostgreSQLSecretStoreIdentity(index, "cloudring-database", "cloudring-postgresql-backup", "cloudring-postgresql-backup-reader", "cloudring-postgresql-backup-token-request", "kubernetes-cloudring-database") {
		return errors.New("PostgreSQL namespaced backup secret-store identity is invalid")
	}
	cluster := index["Cluster/cloudring-database/cloudring-postgres"].Data
	if nestedNumber(cluster, "spec", "instances") != 3 ||
		nestedString(cluster, "spec", "imageName") != "ghcr.io/cloudnative-pg/postgresql:18.4@sha256:17760b4508e1703f7bf3d5ee6c9335ff6d1bf62b034a3d5b32a43414a516789f" ||
		!exactBool(cluster, false, "spec", "enableSuperuserAccess") ||
		!exactBool(cluster, true, "spec", "enablePDB") ||
		nestedString(cluster, "spec", "primaryUpdateMethod") != "switchover" ||
		nestedString(cluster, "spec", "primaryUpdateStrategy") != "unsupervised" ||
		nestedString(cluster, "metadata", "annotations", "cloudring.org/non-claim") == "" {
		return errors.New("PostgreSQL cluster HA boundary is invalid")
	}
	if nestedString(cluster, "spec", "bootstrap", "initdb", "database") != "cloudring" ||
		nestedString(cluster, "spec", "bootstrap", "initdb", "owner") != "cloudring_owner" ||
		nestedString(cluster, "spec", "bootstrap", "initdb", "secret", "name") != "cloudring-postgres-owner" ||
		!exactBool(cluster, true, "spec", "bootstrap", "initdb", "dataChecksums") {
		return errors.New("PostgreSQL bootstrap identity is invalid")
	}
	roles, ok := nested(cluster, "spec", "managed", "roles").([]any)
	if !ok || len(roles) != 1 {
		return errors.New("PostgreSQL managed application role is invalid")
	}
	applicationRole, ok := roles[0].(map[string]any)
	if !ok || !exactMappingKeys(applicationRole,
		"name", "ensure", "comment", "login", "superuser", "createdb", "createrole",
		"inherit", "replication", "bypassrls", "connectionLimit", "passwordSecret") ||
		nestedString(applicationRole, "name") != "cloudring_app" ||
		nestedString(applicationRole, "ensure") != "present" ||
		nestedString(applicationRole, "comment") == "" ||
		!exactBool(applicationRole, true, "login") ||
		!exactBool(applicationRole, false, "superuser") ||
		!exactBool(applicationRole, false, "createdb") ||
		!exactBool(applicationRole, false, "createrole") ||
		!exactBool(applicationRole, true, "inherit") ||
		!exactBool(applicationRole, false, "replication") ||
		!exactBool(applicationRole, false, "bypassrls") ||
		nestedNumber(applicationRole, "connectionLimit") != 50 ||
		nestedString(applicationRole, "passwordSecret", "name") != "cloudring-postgres-app" {
		return errors.New("PostgreSQL managed application role is invalid")
	}
	if nestedString(cluster, "spec", "postgresql", "parameters", "password_encryption") != "scram-sha-256" ||
		nestedString(cluster, "spec", "postgresql", "parameters", "ssl_min_protocol_version") != "TLSv1.3" ||
		nestedString(cluster, "spec", "postgresql", "parameters", "synchronous_commit") != "remote_apply" ||
		nested(cluster, "spec", "postgresql", "pg_hba") != nil {
		return errors.New("PostgreSQL authentication or TLS policy is invalid")
	}
	if nestedString(cluster, "spec", "postgresql", "synchronous", "method") != "any" ||
		nestedNumber(cluster, "spec", "postgresql", "synchronous", "number") != 1 ||
		nestedString(cluster, "spec", "postgresql", "synchronous", "dataDurability") != "required" ||
		!exactBool(cluster, true, "spec", "postgresql", "synchronous", "failoverQuorum") {
		return errors.New("PostgreSQL synchronous durability policy is invalid")
	}
	if !exactBool(cluster, true, "spec", "affinity", "enablePodAntiAffinity") ||
		nestedString(cluster, "spec", "affinity", "podAntiAffinityType") != "required" ||
		nestedString(cluster, "spec", "affinity", "topologyKey") != "kubernetes.io/hostname" ||
		nestedString(cluster, "spec", "affinity", "nodeSelector", "kubernetes.io/os") != "linux" {
		return errors.New("PostgreSQL failure-domain placement is invalid")
	}
	for _, path := range []string{"storage", "walStorage"} {
		if nestedString(cluster, "spec", path, "storageClass") != "longhorn-replicated" ||
			nestedString(cluster, "spec", path, "size") == "" ||
			!exactBool(cluster, true, "spec", path, "resizeInUseVolumes") {
			return errors.New("PostgreSQL replicated storage is invalid")
		}
	}
	plugins, ok := nested(cluster, "spec", "plugins").([]any)
	if !ok || len(plugins) != 1 {
		return errors.New("PostgreSQL WAL archiver plugin is invalid")
	}
	plugin, ok := plugins[0].(map[string]any)
	if !ok || !exactMappingKeys(plugin, "name", "isWALArchiver", "parameters") ||
		nestedString(plugin, "name") != "barman-cloud.cloudnative-pg.io" ||
		!exactBool(plugin, true, "isWALArchiver") ||
		!exactMappingKeys(nested(plugin, "parameters"), "barmanObjectName") ||
		nestedString(plugin, "parameters", "barmanObjectName") != "cloudring-postgres-offcell" {
		return errors.New("PostgreSQL WAL archiver plugin is invalid")
	}
	if nestedString(cluster, "spec", "backup", "target") != "prefer-standby" ||
		nestedString(cluster, "spec", "backup", "volumeSnapshot", "className") != "longhorn-retain" ||
		nestedString(cluster, "spec", "backup", "volumeSnapshot", "walClassName") != "longhorn-retain" ||
		nestedString(cluster, "spec", "backup", "volumeSnapshot", "snapshotOwnerReference") != "none" ||
		!exactBool(cluster, true, "spec", "backup", "volumeSnapshot", "online") {
		return errors.New("PostgreSQL retained snapshot policy is invalid")
	}
	backup := index["ScheduledBackup/cloudring-database/cloudring-postgres-volume-snapshot"].Data
	if nestedString(backup, "spec", "method") != "volumeSnapshot" ||
		nestedString(backup, "spec", "backupOwnerReference") != "self" ||
		nestedString(backup, "spec", "cluster", "name") != "cloudring-postgres" ||
		nestedString(backup, "spec", "schedule") != "0 0 */6 * * *" ||
		!exactBool(backup, false, "spec", "immediate") {
		return errors.New("PostgreSQL scheduled backup is invalid")
	}
	externalSecret := index["ExternalSecret/cloudring-database/cloudring-postgres-offcell-s3"].Data
	if !exactPostgreSQLExternalSecret(externalSecret, "cloudring-postgresql-backup", "cloudring-postgres-offcell-s3", "services/postgresql/offcell-s3", "Retain") {
		return errors.New("PostgreSQL off-cell credential projection is invalid")
	}
	store := index["ObjectStore/cloudring-database/cloudring-postgres-offcell"].Data
	if nestedString(store, "apiVersion") != "barmancloud.cnpg.io/v1" ||
		nestedString(store, "metadata", "annotations", "cloudring.org/off-cell-required") != "true" ||
		nestedString(store, "metadata", "annotations", "cloudring.org/object-lock-required") != "governance-or-compliance" ||
		nestedString(store, "metadata", "annotations", "cloudring.org/object-lock-minimum-days") != "30" ||
		nestedString(store, "metadata", "annotations", "cloudring.org/non-claim") == "" ||
		nestedString(store, "spec", "retentionPolicy") != "30d" ||
		nestedString(store, "spec", "configuration", "destinationPath") != "s3://cloudring-postgresql-offcell/cloudring-postgres" ||
		nestedString(store, "spec", "configuration", "s3Credentials", "accessKeyId", "name") != "cloudring-postgres-offcell-s3" ||
		nestedString(store, "spec", "configuration", "s3Credentials", "accessKeyId", "key") != "ACCESS_KEY_ID" ||
		nestedString(store, "spec", "configuration", "s3Credentials", "secretAccessKey", "name") != "cloudring-postgres-offcell-s3" ||
		nestedString(store, "spec", "configuration", "s3Credentials", "secretAccessKey", "key") != "ACCESS_SECRET_KEY" ||
		nestedString(store, "spec", "configuration", "data", "compression") != "gzip" ||
		nestedString(store, "spec", "configuration", "data", "encryption") != "AES256" ||
		nestedNumber(store, "spec", "configuration", "data", "jobs") != 2 ||
		!exactBool(store, true, "spec", "configuration", "data", "immediateCheckpoint") ||
		nestedString(store, "spec", "configuration", "wal", "compression") != "gzip" ||
		nestedString(store, "spec", "configuration", "wal", "encryption") != "AES256" ||
		nestedNumber(store, "spec", "configuration", "wal", "maxParallel") != 8 ||
		nested(store, "spec", "configuration", "endpointURL") != nil {
		return errors.New("PostgreSQL off-cell object store is invalid")
	}
	offCellBackup := index["ScheduledBackup/cloudring-database/cloudring-postgres-offcell"].Data
	if nestedString(offCellBackup, "spec", "method") != "plugin" ||
		nestedString(offCellBackup, "spec", "pluginConfiguration", "name") != "barman-cloud.cloudnative-pg.io" ||
		nestedString(offCellBackup, "spec", "backupOwnerReference") != "self" ||
		nestedString(offCellBackup, "spec", "target") != "prefer-standby" ||
		nestedString(offCellBackup, "spec", "cluster", "name") != "cloudring-postgres" ||
		nestedString(offCellBackup, "spec", "schedule") != "0 30 0 * * *" ||
		!exactBool(offCellBackup, false, "spec", "immediate") {
		return errors.New("PostgreSQL off-cell scheduled base backup is invalid")
	}
	policy := index["NetworkPolicy/cloudring-database/cloudring-postgres-ingress"].Data
	if nestedString(policy, "spec", "podSelector", "matchLabels", "cnpg.io/cluster") != "cloudring-postgres" ||
		!exactStringSequence(nested(policy, "spec", "policyTypes"), "Ingress") ||
		lenSequence(nested(policy, "spec", "ingress")) != 4 || nested(policy, "spec", "egress") != nil ||
		!postgresqlCrossNamespaceClientPolicy(policy) {
		return errors.New("PostgreSQL network boundary is invalid")
	}
	return nil
}

func exactPostgreSQLExternalSecret(secret map[string]any, storeName, target, remoteKey, deletionPolicy string) bool {
	if nestedString(secret, "apiVersion") != "external-secrets.io/v1" ||
		nestedString(secret, "spec", "refreshInterval") != "1h" ||
		nestedString(secret, "spec", "secretStoreRef", "kind") != "SecretStore" ||
		nestedString(secret, "spec", "secretStoreRef", "name") != storeName ||
		nestedString(secret, "spec", "target", "name") != target ||
		nestedString(secret, "spec", "target", "creationPolicy") != "Owner" ||
		nestedString(secret, "spec", "target", "deletionPolicy") != deletionPolicy ||
		nestedString(secret, "spec", "target", "template", "metadata", "labels", "cnpg.io/reload") != "true" ||
		nestedString(secret, "metadata", "annotations", "cloudring.org/non-claim") == "" {
		return false
	}
	data, ok := nested(secret, "spec", "data").([]any)
	if !ok || len(data) != 2 {
		return false
	}
	return exactPostgreSQLExternalSecretData(data[0], remoteKey, "ACCESS_KEY_ID", "access-key-id") &&
		exactPostgreSQLExternalSecretData(data[1], remoteKey, "ACCESS_SECRET_KEY", "secret-access-key")
}

func exactPostgreSQLSecretStoreIdentity(
	index map[string]object,
	namespace, storeName, readerName, tokenRoleName, mountPath string,
) bool {
	reader := index["ServiceAccount/"+namespace+"/"+readerName].Data
	if !exactBool(reader, false, "automountServiceAccountToken") {
		return false
	}
	role := index["Role/"+namespace+"/"+tokenRoleName].Data
	rules, ok := nested(role, "rules").([]any)
	if !ok || len(rules) != 1 {
		return false
	}
	rule, ok := rules[0].(map[string]any)
	if !ok || !exactMappingKeys(rule, "apiGroups", "resources", "resourceNames", "verbs") ||
		!exactStringSequence(rule["apiGroups"], "") ||
		!exactStringSequence(rule["resources"], "serviceaccounts/token") ||
		!exactStringSequence(rule["resourceNames"], readerName) ||
		!exactStringSequence(rule["verbs"], "create") {
		return false
	}
	binding := index["RoleBinding/"+namespace+"/"+tokenRoleName].Data
	if nestedString(binding, "roleRef", "apiGroup") != "rbac.authorization.k8s.io" ||
		nestedString(binding, "roleRef", "kind") != "Role" ||
		nestedString(binding, "roleRef", "name") != tokenRoleName ||
		!exactPostgreSQLServiceAccountSubject(nested(binding, "subjects"), "external-secrets", "external-secrets") {
		return false
	}
	store := index["SecretStore/"+namespace+"/"+storeName].Data
	return nestedString(store, "apiVersion") == "external-secrets.io/v1" &&
		nestedString(store, "metadata", "annotations", "cloudring.org/non-claim") != "" &&
		nestedString(store, "spec", "provider", "vault", "server") == "https://openbao-active.openbao.svc:8200" &&
		nestedString(store, "spec", "provider", "vault", "path") == "cloudring" &&
		nestedString(store, "spec", "provider", "vault", "version") == "v2" &&
		nestedString(store, "spec", "provider", "vault", "caProvider", "type") == "ConfigMap" &&
		nestedString(store, "spec", "provider", "vault", "caProvider", "name") == "openbao-client-ca" &&
		nestedString(store, "spec", "provider", "vault", "caProvider", "key") == "ca.crt" &&
		nested(store, "spec", "provider", "vault", "caProvider", "namespace") == nil &&
		nestedString(store, "spec", "provider", "vault", "auth", "kubernetes", "mountPath") == mountPath &&
		nestedString(store, "spec", "provider", "vault", "auth", "kubernetes", "role") == storeName &&
		nestedString(store, "spec", "provider", "vault", "auth", "kubernetes", "serviceAccountRef", "name") == readerName &&
		nested(store, "spec", "provider", "vault", "auth", "kubernetes", "serviceAccountRef", "namespace") == nil &&
		exactStringSequence(nested(store, "spec", "provider", "vault", "auth", "kubernetes", "serviceAccountRef", "audiences"), "openbao")
}

func exactPostgreSQLExternalSecretData(raw any, remoteKey, outputKey, property string) bool {
	item, ok := raw.(map[string]any)
	return ok && exactMappingKeys(item, "secretKey", "remoteRef") &&
		nestedString(item, "secretKey") == outputKey &&
		nestedString(item, "remoteRef", "key") == remoteKey &&
		nestedString(item, "remoteRef", "property") == property &&
		nestedString(item, "remoteRef", "conversionStrategy") == "Default" &&
		nestedString(item, "remoteRef", "decodingStrategy") == "None" &&
		nestedString(item, "remoteRef", "metadataPolicy") == "None"
}

func validatePostgreSQLHARecovery(index map[string]object) error {
	namespace := index["Namespace//cloudring-database-recovery"].Data
	if nestedString(namespace, "metadata", "labels", "cloudring.org/postgresql-recovery-only") != "true" ||
		nestedString(namespace, "metadata", "labels", "cloudring.org/openbao-client") != "true" ||
		nestedString(namespace, "metadata", "labels", "pod-security.kubernetes.io/enforce") != "restricted" {
		return errors.New("PostgreSQL recovery namespace is invalid")
	}
	if !exactPostgreSQLSecretStoreIdentity(index, "cloudring-database-recovery", "cloudring-postgresql-recovery", "cloudring-postgresql-recovery-reader", "cloudring-postgresql-recovery-token-request", "kubernetes-cloudring-database-recovery") {
		return errors.New("PostgreSQL namespaced recovery secret-store identity is invalid")
	}
	externalSecret := index["ExternalSecret/cloudring-database-recovery/cloudring-postgres-offcell-recovery-s3"].Data
	if !exactPostgreSQLExternalSecret(externalSecret, "cloudring-postgresql-recovery", "cloudring-postgres-offcell-recovery-s3", "services/postgresql/offcell-recovery-s3", "Delete") ||
		nestedString(externalSecret, "spec", "target", "template", "metadata", "labels", "cloudring.org/recovery-credential") != "true" {
		return errors.New("PostgreSQL recovery credential projection is invalid")
	}
	recoveryDatabaseSecret := index["ExternalSecret/cloudring-database-recovery/cloudring-postgres-recovery-database"].Data
	if !exactPostgreSQLRecoveryDatabaseSecret(recoveryDatabaseSecret) {
		return errors.New("PostgreSQL recovery-only database credential projection is invalid")
	}
	validator := index["ServiceAccount/cloudring-database-recovery/cloudring-postgres-recovery-validator"].Data
	if !exactBool(validator, false, "automountServiceAccountToken") ||
		nestedString(validator, "metadata", "labels", "cloudring.org/postgresql-recovery-validator") != "true" {
		return errors.New("PostgreSQL recovery validator identity is invalid")
	}
	store := index["ObjectStore/cloudring-database-recovery/cloudring-postgres-offcell-recovery"].Data
	if nestedString(store, "apiVersion") != "barmancloud.cnpg.io/v1" ||
		nestedString(store, "metadata", "annotations", "cloudring.org/off-cell-required") != "true" ||
		nestedString(store, "metadata", "annotations", "cloudring.org/recovery-read-only-credentials-required") != "true" ||
		nestedString(store, "metadata", "annotations", "cloudring.org/non-claim") == "" ||
		nestedString(store, "spec", "configuration", "destinationPath") != "s3://cloudring-postgresql-offcell/cloudring-postgres" ||
		nestedString(store, "spec", "configuration", "s3Credentials", "accessKeyId", "name") != "cloudring-postgres-offcell-recovery-s3" ||
		nestedString(store, "spec", "configuration", "s3Credentials", "accessKeyId", "key") != "ACCESS_KEY_ID" ||
		nestedString(store, "spec", "configuration", "s3Credentials", "secretAccessKey", "name") != "cloudring-postgres-offcell-recovery-s3" ||
		nestedString(store, "spec", "configuration", "s3Credentials", "secretAccessKey", "key") != "ACCESS_SECRET_KEY" ||
		nestedNumber(store, "spec", "configuration", "wal", "maxParallel") != 8 ||
		nested(store, "spec", "retentionPolicy") != nil || nested(store, "spec", "configuration", "endpointURL") != nil {
		return errors.New("PostgreSQL recovery object store is invalid")
	}
	cluster := index["Cluster/cloudring-database-recovery/cloudring-postgres-recovery"].Data
	if nestedNumber(cluster, "spec", "instances") != 1 ||
		nestedString(cluster, "spec", "imageName") != "ghcr.io/cloudnative-pg/postgresql:18.4@sha256:17760b4508e1703f7bf3d5ee6c9335ff6d1bf62b034a3d5b32a43414a516789f" ||
		!exactBool(cluster, false, "spec", "enableSuperuserAccess") ||
		!exactBool(cluster, false, "spec", "enablePDB") ||
		nestedString(cluster, "metadata", "labels", "cloudring.org/postgresql-recovery-only") != "true" ||
		nestedString(cluster, "metadata", "annotations", "cloudring.org/production-route-prohibited") != "true" ||
		nestedString(cluster, "metadata", "annotations", "cloudring.org/non-claim") == "" ||
		nestedString(cluster, "spec", "bootstrap", "recovery", "source") != "cloudring-postgres-source" ||
		nestedString(cluster, "spec", "bootstrap", "recovery", "database") != "cloudring" ||
		nestedString(cluster, "spec", "bootstrap", "recovery", "owner") != "cloudring_owner" ||
		nestedString(cluster, "spec", "bootstrap", "recovery", "secret", "name") != "cloudring-postgres-recovery-owner" ||
		nested(cluster, "spec", "bootstrap", "initdb") != nil ||
		nested(cluster, "spec", "managed") != nil || nested(cluster, "spec", "plugins") != nil {
		return errors.New("PostgreSQL isolated recovery cluster is invalid")
	}
	externalClusters, ok := nested(cluster, "spec", "externalClusters").([]any)
	if !ok || len(externalClusters) != 1 {
		return errors.New("PostgreSQL recovery source is invalid")
	}
	source, ok := externalClusters[0].(map[string]any)
	if !ok || !exactMappingKeys(source, "name", "plugin") ||
		nestedString(source, "name") != "cloudring-postgres-source" ||
		nestedString(source, "plugin", "name") != "barman-cloud.cloudnative-pg.io" ||
		nestedString(source, "plugin", "parameters", "barmanObjectName") != "cloudring-postgres-offcell-recovery" ||
		nestedString(source, "plugin", "parameters", "serverName") != "cloudring-postgres" {
		return errors.New("PostgreSQL recovery source is invalid")
	}
	for _, path := range []string{"storage", "walStorage"} {
		if nestedString(cluster, "spec", path, "storageClass") != "longhorn-replicated" ||
			nestedString(cluster, "spec", path, "size") == "" ||
			!exactBool(cluster, true, "spec", path, "resizeInUseVolumes") {
			return errors.New("PostgreSQL recovery storage is invalid")
		}
	}
	policy := index["NetworkPolicy/cloudring-database-recovery/cloudring-postgres-recovery-isolation"].Data
	if nestedString(policy, "spec", "podSelector", "matchLabels", "cnpg.io/cluster") != "cloudring-postgres-recovery" ||
		!exactStringSequence(nested(policy, "spec", "policyTypes"), "Ingress", "Egress") ||
		lenSequence(nested(policy, "spec", "ingress")) != 2 || lenSequence(nested(policy, "spec", "egress")) != 1 ||
		!postgresqlRecoveryValidatorOnly(policy) {
		return errors.New("PostgreSQL recovery network isolation is invalid")
	}
	apiBinding := index["NetworkPolicy/cloudring-database-recovery/cloudring-postgres-recovery-kubernetes-api-egress-binding"].Data
	if !exactPostgreSQLRecoveryEgressBinding(apiBinding, "192.0.2.1/32", 443, "exact-private-kubernetes-api-cidr-and-port") {
		return errors.New("PostgreSQL recovery Kubernetes API egress binding is invalid")
	}
	objectStoreBinding := index["NetworkPolicy/cloudring-database-recovery/cloudring-postgres-recovery-object-store-egress-binding"].Data
	if !exactPostgreSQLRecoveryEgressBinding(objectStoreBinding, "192.0.2.2/32", 443, "exact-dedicated-off-cell-object-store-cidr-and-tls-port") {
		return errors.New("PostgreSQL recovery object-store egress binding is invalid")
	}
	return nil
}

func exactPostgreSQLRecoveryDatabaseSecret(secret map[string]any) bool {
	if nestedString(secret, "apiVersion") != "external-secrets.io/v1" ||
		nestedString(secret, "metadata", "annotations", "cloudring.org/non-claim") == "" ||
		nestedString(secret, "spec", "refreshInterval") != "1h" ||
		nestedString(secret, "spec", "secretStoreRef", "kind") != "SecretStore" ||
		nestedString(secret, "spec", "secretStoreRef", "name") != "cloudring-postgresql-recovery" ||
		nestedString(secret, "spec", "target", "name") != "cloudring-postgres-recovery-owner" ||
		nestedString(secret, "spec", "target", "creationPolicy") != "Owner" ||
		nestedString(secret, "spec", "target", "deletionPolicy") != "Delete" ||
		nestedString(secret, "spec", "target", "template", "type") != "kubernetes.io/basic-auth" ||
		nestedString(secret, "spec", "target", "template", "metadata", "labels", "cnpg.io/reload") != "true" ||
		nestedString(secret, "spec", "target", "template", "metadata", "labels", "cloudring.org/recovery-credential") != "true" {
		return false
	}
	data, ok := nested(secret, "spec", "data").([]any)
	return ok && len(data) == 2 &&
		exactPostgreSQLExternalSecretData(data[0], "services/postgresql/recovery-database", "username", "username") &&
		exactPostgreSQLExternalSecretData(data[1], "services/postgresql/recovery-database", "password", "password")
}

func postgresqlRecoveryValidatorOnly(policy map[string]any) bool {
	ingress, ok := nested(policy, "spec", "ingress").([]any)
	if !ok || len(ingress) != 2 {
		return false
	}
	validatorReady := false
	operatorReady := false
	for _, rawRule := range ingress {
		rule, ruleOK := rawRule.(map[string]any)
		if !ruleOK || !exactMappingKeys(rule, "from", "ports") {
			return false
		}
		from, fromOK := rule["from"].([]any)
		ports, portsOK := rule["ports"].([]any)
		if !fromOK || !portsOK || len(from) != 1 || len(ports) != 1 {
			return false
		}
		peer, peerOK := from[0].(map[string]any)
		port, portOK := ports[0].(map[string]any)
		if !peerOK || !portOK || nestedString(port, "protocol") != "TCP" {
			return false
		}
		switch {
		case exactMappingKeys(peer, "podSelector") &&
			nestedString(peer, "podSelector", "matchLabels", "cloudring.org/postgresql-recovery-validator") == "true" &&
			nestedNumber(port, "port") == 5432:
			validatorReady = true
		case exactMappingKeys(peer, "namespaceSelector", "podSelector") &&
			nestedString(peer, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") == "cnpg-system" &&
			nestedString(peer, "podSelector", "matchLabels", "app.kubernetes.io/instance") == "cnpg" &&
			nestedString(peer, "podSelector", "matchLabels", "app.kubernetes.io/name") == "cloudnative-pg" &&
			nestedNumber(port, "port") == 8000:
			operatorReady = true
		default:
			return false
		}
	}
	egress, ok := nested(policy, "spec", "egress").([]any)
	if !ok || len(egress) != 1 {
		return false
	}
	dnsRule, ok := egress[0].(map[string]any)
	if !ok || !exactMappingKeys(dnsRule, "to", "ports") {
		return false
	}
	to, toOK := dnsRule["to"].([]any)
	dnsPorts, portsOK := dnsRule["ports"].([]any)
	if !toOK || !portsOK || len(to) != 1 || len(dnsPorts) != 2 {
		return false
	}
	dnsPeer, peerOK := to[0].(map[string]any)
	udpPort, udpOK := dnsPorts[0].(map[string]any)
	tcpPort, tcpOK := dnsPorts[1].(map[string]any)
	dnsReady := peerOK && exactMappingKeys(dnsPeer, "namespaceSelector", "podSelector") &&
		nestedString(dnsPeer, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") == "kube-system" &&
		nestedString(dnsPeer, "podSelector", "matchLabels", "k8s-app") == "kube-dns" &&
		udpOK && nestedString(udpPort, "protocol") == "UDP" && nestedNumber(udpPort, "port") == 53 &&
		tcpOK && nestedString(tcpPort, "protocol") == "TCP" && nestedNumber(tcpPort, "port") == 53
	return validatorReady && operatorReady && dnsReady
}

func exactPostgreSQLRecoveryEgressBinding(policy map[string]any, cidr string, port int, binding string) bool {
	if nestedString(policy, "metadata", "annotations", "cloudring.org/non-claim") == "" ||
		nestedString(policy, "metadata", "annotations", "cloudring.org/site-binding-required") != binding ||
		nestedString(policy, "spec", "podSelector", "matchLabels", "cnpg.io/cluster") != "cloudring-postgres-recovery" ||
		!exactStringSequence(nested(policy, "spec", "policyTypes"), "Egress") || nested(policy, "spec", "ingress") != nil {
		return false
	}
	egress, ok := nested(policy, "spec", "egress").([]any)
	if !ok || len(egress) != 1 {
		return false
	}
	rule, ok := egress[0].(map[string]any)
	if !ok || !exactMappingKeys(rule, "to", "ports") {
		return false
	}
	to, toOK := rule["to"].([]any)
	ports, portsOK := rule["ports"].([]any)
	if !toOK || !portsOK || len(to) != 1 || len(ports) != 1 {
		return false
	}
	peer, peerOK := to[0].(map[string]any)
	targetPort, portOK := ports[0].(map[string]any)
	return peerOK && portOK && exactMappingKeys(peer, "ipBlock") &&
		nestedString(peer, "ipBlock", "cidr") == cidr && nested(peer, "ipBlock", "except") == nil &&
		nestedString(targetPort, "protocol") == "TCP" && nestedNumber(targetPort, "port") == port
}

func postgresqlCrossNamespaceClientPolicy(policy map[string]any) bool {
	ingress, _ := nested(policy, "spec", "ingress").([]any)
	for _, rawRule := range ingress {
		rule, _ := rawRule.(map[string]any)
		from, _ := rule["from"].([]any)
		if len(from) != 1 {
			continue
		}
		peer, _ := from[0].(map[string]any)
		if nestedString(peer, "namespaceSelector", "matchLabels", "cloudring.org/postgresql-client-namespace") == "true" &&
			nestedString(peer, "podSelector", "matchLabels", "cloudring.org/postgresql-client") == "true" {
			return true
		}
	}
	return false
}

func lenSequence(value any) int {
	items, _ := value.([]any)
	return len(items)
}
