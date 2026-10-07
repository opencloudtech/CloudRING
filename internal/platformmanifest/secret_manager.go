// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package platformmanifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/opencloudtech/CloudRING/pkg/openbaoexecutor"
	"gopkg.in/yaml.v3"
)

const (
	profilePath                  = "deploy/kubernetes/secret-manager"
	maxFileBytes                 = 1 << 20
	openBaoReadinessPatchPath    = "/spec/template/spec/containers/0/readinessProbe/exec/command"
	bootstrapExecutorProfilePath = "contracts/openbao-kubernetes-auth/fixtures/synthetic-kubernetes-auth-executor.json"
	openBaoReadinessShellCommand = `pod_dns="${BAO_K8S_POD_NAME:?}.openbao-internal"
pod_dns="${pod_dns}.${BAO_K8S_NAMESPACE:?}.svc"
export BAO_ADDR="https://${pod_dns}:8200"
export BAO_CACERT="/openbao/tls/client/ca.crt"
export BAO_TLS_SERVER_NAME="${pod_dns}"
exec bao status`
)

type Report struct {
	Status     string   `json:"status"`
	LiveStatus string   `json:"liveStatus,omitempty"`
	Profile    string   `json:"profile"`
	Files      int      `json:"files"`
	Documents  int      `json:"documents"`
	Checks     []string `json:"checks"`
	Blockers   []string `json:"blockers,omitempty"`
	NonClaims  []string `json:"nonClaims,omitempty"`
}

type object struct {
	Kind      string
	Name      string
	Namespace string
	Data      map[string]any
}

type openBaoHCL struct {
	UI                   bool                     `hcl:"ui"`
	Listeners            []openBaoListener        `hcl:"listener,block"`
	Storage              []openBaoStorage         `hcl:"storage,block"`
	Audits               []openBaoAudit           `hcl:"audit,block"`
	ServiceRegistrations []openBaoServiceRegistry `hcl:"service_registration,block"`
}

type openBaoListener struct {
	Type            string `hcl:"type,label"`
	Address         string `hcl:"address"`
	ClusterAddress  string `hcl:"cluster_address"`
	TLSDisable      int    `hcl:"tls_disable"`
	TLSCertFile     string `hcl:"tls_cert_file"`
	TLSKeyFile      string `hcl:"tls_key_file"`
	TLSClientCAFile string `hcl:"tls_client_ca_file"`
}

type openBaoStorage struct {
	Type      string             `hcl:"type,label"`
	Path      string             `hcl:"path"`
	RetryJoin []openBaoRetryJoin `hcl:"retry_join,block"`
}

type openBaoRetryJoin struct {
	LeaderAPIAddress     string `hcl:"leader_api_addr"`
	LeaderCACertFile     string `hcl:"leader_ca_cert_file"`
	LeaderClientCertFile string `hcl:"leader_client_cert_file"`
	LeaderClientKeyFile  string `hcl:"leader_client_key_file"`
	LeaderTLSServerName  string `hcl:"leader_tls_servername"`
}

type openBaoServiceRegistry struct {
	Type string `hcl:"type,label"`
}

type openBaoAudit struct {
	Type        string              `hcl:"type,label"`
	Name        string              `hcl:"name,label"`
	Description string              `hcl:"description"`
	Options     openBaoAuditOptions `hcl:"options,block"`
}

type openBaoAuditOptions struct {
	FilePath string `hcl:"file_path"`
	Mode     string `hcl:"mode"`
	LogRaw   string `hcl:"log_raw"`
}

// VerifySecretManager validates the source contract without contacting a
// cluster or chart registry. It complements, but does not replace, Helm render
// and live readiness checks.
func VerifySecretManager(root string) (Report, error) {
	root, err := canonicalRoot(root)
	if err != nil {
		return Report{}, err
	}
	report := Report{Status: "blocked", Profile: "cloudring-runtime-secret-manager/v1"}
	repository, err := os.OpenRoot(root)
	if err != nil {
		return report, errors.New("open confined repository root")
	}
	defer repository.Close()
	var objects []object
	for _, stage := range []string{"controllers", "runtime", "store", "consumer-example"} {
		stageObjects, files, readErr := readStage(repository, stage)
		if readErr != nil {
			return report, readErr
		}
		report.Files += files
		objects = append(objects, stageObjects...)
	}
	report.Documents = len(objects)
	if len(objects) != 33 {
		return report, fmt.Errorf("secret-manager document count is %d, want 33", len(objects))
	}
	if err := verifyCanonicalBootstrapExecutor(repository); err != nil {
		return report, err
	}
	report.Files++
	if err := validateObjects(objects); err != nil {
		return report, err
	}
	report.Status = "ready"
	report.Checks = []string{
		"source_stages_separated",
		"yaml_duplicate_keys_absent",
		"secret_material_absent",
		"controller_versions_and_images_pinned",
		"openbao_tls_ha_raft_retention_and_probe_ready",
		"external_secrets_workload_identity_ready",
		"external_secrets_token_request_rbac_least_privilege",
		"namespaced_consumer_identity_example_ready",
		"openbao_apply_executor_rbac_and_lease_ready",
	}
	return report, nil
}

func verifyCanonicalBootstrapExecutor(repository *os.Root) error {
	profileData, err := readRegular(repository, bootstrapExecutorProfilePath)
	if err != nil {
		return errors.New("read canonical OpenBao executor profile")
	}
	profile, problems := openbaoexecutor.Parse(profileData)
	if len(problems) != 0 {
		return errors.New("canonical OpenBao executor profile is invalid")
	}
	manifest, err := readRegular(repository, filepath.Join(profilePath, "consumer-example", "bootstrap-executor.yaml"))
	if err != nil {
		return errors.New("read canonical OpenBao executor manifest")
	}
	if err := openbaoexecutor.VerifyRendered(profile, manifest); err != nil {
		return errors.New("consumer example OpenBao apply executor boundary is invalid")
	}
	return nil
}

func canonicalRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", errors.New("resolve repository root")
	}
	info, err := os.Lstat(abs)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("repository root is not an exact directory")
	}
	return abs, nil
}

func readStage(root *os.Root, stage string) ([]object, int, error) {
	dir := filepath.Join(profilePath, stage)
	kustomization, err := readRegular(root, filepath.Join(dir, "kustomization.yaml"))
	if err != nil {
		return nil, 0, err
	}
	var manifest map[string]any
	if err := decodeOne(kustomization, &manifest); err != nil || len(manifest) != 3 || stringValue(manifest["apiVersion"]) != "kustomize.config.k8s.io/v1beta1" || stringValue(manifest["kind"]) != "Kustomization" {
		return nil, 0, fmt.Errorf("%s stage has an invalid kustomization", stage)
	}
	resources, ok := manifest["resources"].([]any)
	if !ok || len(resources) == 0 {
		return nil, 0, fmt.Errorf("%s stage has an invalid kustomization", stage)
	}
	seen := map[string]bool{}
	var result []object
	for _, rawResource := range resources {
		resource := stringValue(rawResource)
		if resource == "" || filepath.Base(resource) != resource || filepath.Ext(resource) != ".yaml" || seen[resource] {
			return nil, 0, fmt.Errorf("%s stage has an unsafe resource reference", stage)
		}
		seen[resource] = true
		data, err := readRegular(root, filepath.Join(dir, resource))
		if err != nil {
			return nil, 0, err
		}
		if bytes.Contains(data, []byte("REPLACE_WITH")) || bytes.Contains(data, []byte("example.invalid")) || bytes.Contains(data, []byte(":latest")) {
			return nil, 0, fmt.Errorf("%s contains an unresolved or mutable runtime reference", resource)
		}
		documents, err := decodeObjects(data)
		if err != nil {
			return nil, 0, fmt.Errorf("decode %s: %w", resource, err)
		}
		result = append(result, documents...)
	}
	return result, len(resources) + 1, nil
}

func readRegular(root *os.Root, path string) ([]byte, error) {
	info, err := root.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxFileBytes {
		return nil, errors.New("manifest input is not an exact bounded regular file")
	}
	data, err := root.ReadFile(path)
	if err != nil || int64(len(data)) != info.Size() {
		return nil, errors.New("read exact manifest input")
	}
	after, err := root.Lstat(path)
	if err != nil || !os.SameFile(info, after) || after.Size() != info.Size() || after.ModTime() != info.ModTime() {
		return nil, errors.New("manifest input changed while reading")
	}
	return data, nil
}

func decodeOne(data []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var node yaml.Node
	if err := decoder.Decode(&node); err != nil {
		return err
	}
	if err := rejectDuplicateKeys(&node); err != nil {
		return err
	}
	if err := node.Decode(target); err != nil {
		return err
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing YAML document")
	}
	return nil
}

func decodeObjects(data []byte) ([]object, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var result []object
	for {
		var node yaml.Node
		err := decoder.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(node.Content) == 0 {
			continue
		}
		if err := rejectDuplicateKeys(&node); err != nil {
			return nil, err
		}
		var value map[string]any
		if err := node.Decode(&value); err != nil {
			return nil, err
		}
		metadata, _ := value["metadata"].(map[string]any)
		item := object{Kind: stringValue(value["kind"]), Name: stringValue(metadata["name"]), Namespace: stringValue(metadata["namespace"]), Data: value}
		if item.Kind == "" || item.Name == "" {
			return nil, errors.New("manifest object identity is incomplete")
		}
		if item.Kind == "Secret" {
			return nil, errors.New("secret-manager source profile must not contain Secret objects")
		}
		result = append(result, item)
	}
	return result, nil
}

func rejectDuplicateKeys(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index].Value
			if seen[key] {
				return errors.New("duplicate YAML mapping key")
			}
			seen[key] = true
		}
	}
	for _, child := range node.Content {
		if err := rejectDuplicateKeys(child); err != nil {
			return err
		}
	}
	return nil
}

func validateObjects(objects []object) error {
	index := map[string]object{}
	for _, item := range objects {
		key := item.Kind + "/" + item.Namespace + "/" + item.Name
		if _, duplicate := index[key]; duplicate {
			return errors.New("duplicate manifest object identity")
		}
		index[key] = item
	}
	expected := []string{
		"Bundle//openbao-client-ca",
		"Certificate/cert-manager/openbao-root-ca",
		"Certificate/openbao/openbao-server",
		"ClusterIssuer//cloudring-openbao-ca",
		"ClusterIssuer//cloudring-openbao-selfsigned-bootstrap",
		"ClusterRole//cloudring-openbao-exec-6434a933d18dc631c365fc81739ee121c36bd9ac",
		"ClusterRoleBinding//cloudring-openbao-exec-6434a933d18dc631c365fc81739ee121c36bd9ac",
		"ClusterSecretStore//platform-secrets",
		"HelmRelease/cert-manager/trust-manager",
		"HelmRelease/external-secrets/external-secrets",
		"HelmRelease/openbao/openbao",
		"HelmRepository/cert-manager/jetstack",
		"HelmRepository/external-secrets/external-secrets",
		"HelmRepository/openbao/openbao",
		"Lease/cloudring-consumer-example/cloudring-openbao-exec-6434a933d18dc631c365fc81739ee121c36bd9ac",
		"Namespace//cloudring-consumer-example",
		"Namespace//cloudring-consumer-negative-example",
		"Namespace//external-secrets",
		"Namespace//openbao",
		"NetworkPolicy/openbao/openbao-ingress",
		"Role/cloudring-consumer-example/cloudring-openbao-exec-6434a933d18dc631c365fc81739ee121c36bd9ac",
		"Role/cloudring-consumer-example/cloudring-openbao-reader-token-request",
		"Role/cloudring-consumer-negative-example/cloudring-openbao-exec-6434a933d18dc631c365fc81739ee121c36bd9ac",
		"Role/external-secrets/external-secrets-token-request",
		"RoleBinding/cloudring-consumer-example/cloudring-openbao-exec-6434a933d18dc631c365fc81739ee121c36bd9ac",
		"RoleBinding/cloudring-consumer-example/cloudring-openbao-reader-token-request",
		"RoleBinding/cloudring-consumer-negative-example/cloudring-openbao-exec-6434a933d18dc631c365fc81739ee121c36bd9ac",
		"RoleBinding/external-secrets/external-secrets-token-request",
		"SecretStore/cloudring-consumer-example/cloudring-openbao",
		"ServiceAccount/cloudring-consumer-example/cloudring-openbao-bootstrap-executor",
		"ServiceAccount/cloudring-consumer-example/cloudring-openbao-reader",
		"ServiceAccount/cloudring-consumer-example/cloudring-openbao-reader-denied",
		"ServiceAccount/cloudring-consumer-negative-example/cloudring-openbao-reader",
	}
	actual := make([]string, 0, len(index))
	for key := range index {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		return errors.New("secret-manager object inventory is not exact")
	}
	require := func(kind, namespace, name string) (object, error) {
		item, found := index[kind+"/"+namespace+"/"+name]
		if !found {
			return object{}, fmt.Errorf("required %s/%s/%s is missing", kind, namespace, name)
		}
		return item, nil
	}
	trust, err := require("HelmRelease", "cert-manager", "trust-manager")
	if err != nil || nestedString(trust.Data, "spec", "chart", "spec", "version") != "v0.24.0" || nestedString(trust.Data, "spec", "values", "image", "digest") != "sha256:a7c1d71cad37b404738192213e3801dbf89fe797e72664b0ff0d498db35cea74" {
		return errors.New("trust-manager chart or image pin is invalid")
	}
	eso, err := require("HelmRelease", "external-secrets", "external-secrets")
	if err != nil || nestedString(eso.Data, "spec", "chart", "spec", "version") != "2.7.0" || nestedNumber(eso.Data, "spec", "values", "replicaCount") != 3 || nestedBool(eso.Data, "spec", "values", "leaderElect") != true {
		return errors.New("External Secrets HA controller contract is invalid")
	}
	serviceAccountTokenCreate, explicit := nested(eso.Data, "spec", "values", "rbac", "serviceAccountTokenCreate").(bool)
	if !explicit || serviceAccountTokenCreate {
		return errors.New("External Secrets blanket service-account token creation must be explicitly disabled")
	}
	if nested(eso.Data, "spec", "values", "extraObjects") != nil || nested(eso.Data, "spec", "valuesFrom") != nil || nested(eso.Data, "spec", "postRenderers") != nil {
		return errors.New("External Secrets render-time extensions are forbidden")
	}
	if !exactMappingKeys(nested(eso.Data, "spec", "values"), "installCRDs", "replicaCount", "leaderElect", "systemAuthDelegator", "rbac", "image", "webhook", "certController", "podDisruptionBudget", "resources", "concurrent", "vault", "genericTargets", "bitwarden-sdk-server") ||
		!exactMappingKeys(nested(eso.Data, "spec", "values", "rbac"), "serviceAccountTokenCreate") ||
		!exactMappingKeys(nested(eso.Data, "spec", "values", "vault"), "enableTokenCache") ||
		!exactMappingKeys(nested(eso.Data, "spec", "values", "genericTargets"), "enabled") ||
		!exactMappingKeys(nested(eso.Data, "spec", "values", "bitwarden-sdk-server"), "enabled") {
		return errors.New("External Secrets chart values inventory is not exact")
	}
	systemAuthDelegator, systemAuthDelegatorExplicit := nested(eso.Data, "spec", "values", "systemAuthDelegator").(bool)
	genericTargets, genericTargetsExplicit := nested(eso.Data, "spec", "values", "genericTargets", "enabled").(bool)
	bitwardenServer, bitwardenServerExplicit := nested(eso.Data, "spec", "values", "bitwarden-sdk-server", "enabled").(bool)
	tokenCache, tokenCacheExplicit := nested(eso.Data, "spec", "values", "vault", "enableTokenCache").(bool)
	if !systemAuthDelegatorExplicit || systemAuthDelegator || !genericTargetsExplicit || genericTargets || !bitwardenServerExplicit || bitwardenServer || !tokenCacheExplicit || tokenCache {
		return errors.New("External Secrets optional privileged surfaces must be explicitly disabled")
	}
	for _, path := range [][]string{{"spec", "values", "image", "tag"}, {"spec", "values", "webhook", "image", "tag"}, {"spec", "values", "certController", "image", "tag"}} {
		if !digestTagged(nestedString(eso.Data, path...)) {
			return errors.New("External Secrets image is not digest-pinned")
		}
	}
	bao, err := require("HelmRelease", "openbao", "openbao")
	if err != nil || nestedString(bao.Data, "spec", "chart", "spec", "version") != "0.28.4" || !digestTagged(nestedString(bao.Data, "spec", "values", "server", "image", "tag")) {
		return errors.New("OpenBao chart or image pin is invalid")
	}
	if nestedBool(bao.Data, "spec", "values", "global", "tlsDisable") || nestedString(bao.Data, "spec", "values", "server", "podManagementPolicy") != "Parallel" || !nestedBool(bao.Data, "spec", "values", "server", "ha", "enabled") || nestedNumber(bao.Data, "spec", "values", "server", "ha", "replicas") != 3 || nestedString(bao.Data, "spec", "values", "server", "ha", "apiAddr") != "https://openbao-active.openbao.svc:8200" || !nestedBool(bao.Data, "spec", "values", "server", "ha", "raft", "enabled") {
		return errors.New("OpenBao TLS HA Raft contract is invalid")
	}
	if !nestedBool(bao.Data, "spec", "values", "server", "authDelegator", "enabled") {
		return errors.New("OpenBao auth-delegator contract is invalid")
	}
	if _, err := openBaoReadinessPostRenderCommand(bao.Data); err != nil {
		return err
	}
	if err := validateOpenBaoHCL(nestedString(bao.Data, "spec", "values", "server", "ha", "raft", "config")); err != nil {
		return err
	}
	affinity := nestedString(bao.Data, "spec", "values", "server", "affinity")
	if !strings.Contains(affinity, "requiredDuringSchedulingIgnoredDuringExecution") || !strings.Contains(affinity, "topologyKey: kubernetes.io/hostname") || !nestedBool(bao.Data, "spec", "values", "server", "ha", "disruptionBudget", "enabled") || nestedNumber(bao.Data, "spec", "values", "server", "ha", "disruptionBudget", "maxUnavailable") != 1 {
		return errors.New("OpenBao anti-affinity or disruption budget is invalid")
	}
	if !nestedBool(bao.Data, "spec", "values", "server", "dataStorage", "enabled") || !nestedBool(bao.Data, "spec", "values", "server", "auditStorage", "enabled") || nestedString(bao.Data, "spec", "values", "server", "persistentVolumeClaimRetentionPolicy", "whenDeleted") != "Retain" {
		return errors.New("OpenBao durable storage and retention contract is invalid")
	}
	store, err := require("ClusterSecretStore", "", "platform-secrets")
	if err != nil || nestedString(store.Data, "spec", "provider", "vault", "server") != "https://openbao-active.openbao.svc:8200" || nestedString(store.Data, "spec", "provider", "vault", "auth", "kubernetes", "mountPath") != "kubernetes-platform-secrets" || nestedString(store.Data, "spec", "provider", "vault", "auth", "kubernetes", "role") != "cloudring-external-secrets" || nestedString(store.Data, "spec", "provider", "vault", "auth", "kubernetes", "serviceAccountRef", "name") != "external-secrets" || nestedString(store.Data, "spec", "provider", "vault", "auth", "kubernetes", "serviceAccountRef", "namespace") != "external-secrets" || !exactStringSequence(nested(store.Data, "spec", "provider", "vault", "auth", "kubernetes", "serviceAccountRef", "audiences"), "openbao") {
		return errors.New("platform secret-store workload identity contract is invalid")
	}
	if !platformStoreNamespaceBoundary(store.Data) {
		return errors.New("platform secret-store privileged namespace boundary is invalid")
	}
	platformRole, _ := require("Role", "external-secrets", "external-secrets-token-request")
	if !exactTokenRequestRole(platformRole.Data, "external-secrets") {
		return errors.New("platform token-request Role is not least privilege")
	}
	platformBinding, _ := require("RoleBinding", "external-secrets", "external-secrets-token-request")
	if !exactTokenRequestRoleBinding(platformBinding.Data, "external-secrets-token-request", "external-secrets", "external-secrets") {
		return errors.New("platform token-request RoleBinding is not least privilege")
	}
	consumerNamespace, _ := require("Namespace", "", "cloudring-consumer-example")
	if nestedString(consumerNamespace.Data, "apiVersion") != "v1" || !exactStringMap(nested(consumerNamespace.Data, "metadata", "labels"), map[string]string{
		"app.kubernetes.io/part-of":          "cloudring-secret-manager",
		"cloudring.org/openbao-client":       "true",
		"pod-security.kubernetes.io/enforce": "restricted",
		"pod-security.kubernetes.io/audit":   "restricted",
		"pod-security.kubernetes.io/warn":    "restricted",
	}) {
		return errors.New("consumer example namespace security boundary is invalid")
	}
	negativeNamespace, _ := require("Namespace", "", "cloudring-consumer-negative-example")
	if nestedString(negativeNamespace.Data, "apiVersion") != "v1" || !exactStringMap(nested(negativeNamespace.Data, "metadata", "labels"), map[string]string{
		"app.kubernetes.io/part-of":               "cloudring-secret-manager",
		"cloudring.org/openbao-negative-identity": "true",
		"pod-security.kubernetes.io/enforce":      "restricted",
		"pod-security.kubernetes.io/audit":        "restricted",
		"pod-security.kubernetes.io/warn":         "restricted",
	}) {
		return errors.New("consumer example negative namespace security and ownership boundary is invalid")
	}
	consumerServiceAccount, _ := require("ServiceAccount", "cloudring-consumer-example", "cloudring-openbao-reader")
	automount, explicit := nested(consumerServiceAccount.Data, "automountServiceAccountToken").(bool)
	if nestedString(consumerServiceAccount.Data, "apiVersion") != "v1" || !explicit || automount || nested(consumerServiceAccount.Data, "secrets") != nil {
		return errors.New("consumer example service-account identity is invalid")
	}
	consumerRole, _ := require("Role", "cloudring-consumer-example", "cloudring-openbao-reader-token-request")
	if !exactTokenRequestRole(consumerRole.Data, "cloudring-openbao-reader") {
		return errors.New("consumer example token-request Role is not least privilege")
	}
	consumerBinding, _ := require("RoleBinding", "cloudring-consumer-example", "cloudring-openbao-reader-token-request")
	if !exactTokenRequestRoleBinding(consumerBinding.Data, "cloudring-openbao-reader-token-request", "external-secrets", "external-secrets") {
		return errors.New("consumer example token-request RoleBinding is not least privilege")
	}
	consumerStore, _ := require("SecretStore", "cloudring-consumer-example", "cloudring-openbao")
	if !exactConsumerSecretStore(consumerStore.Data) {
		return errors.New("consumer example namespaced SecretStore contract is invalid")
	}
	bootstrapIssuer, _ := require("ClusterIssuer", "", "cloudring-openbao-selfsigned-bootstrap")
	if nested(bootstrapIssuer.Data, "spec", "selfSigned") == nil {
		return errors.New("OpenBao bootstrap issuer is invalid")
	}
	caCertificate, _ := require("Certificate", "cert-manager", "openbao-root-ca")
	if !nestedBool(caCertificate.Data, "spec", "isCA") || nestedString(caCertificate.Data, "spec", "secretName") != "openbao-root-ca" || nestedString(caCertificate.Data, "spec", "issuerRef", "name") != "cloudring-openbao-selfsigned-bootstrap" {
		return errors.New("OpenBao root CA certificate is invalid")
	}
	caIssuer, _ := require("ClusterIssuer", "", "cloudring-openbao-ca")
	if nestedString(caIssuer.Data, "spec", "ca", "secretName") != "openbao-root-ca" {
		return errors.New("OpenBao CA issuer is invalid")
	}
	serverCertificate, _ := require("Certificate", "openbao", "openbao-server")
	if nestedString(serverCertificate.Data, "spec", "secretName") != "openbao-server-tls" || nestedString(serverCertificate.Data, "spec", "issuerRef", "name") != "cloudring-openbao-ca" || nestedString(serverCertificate.Data, "spec", "issuerRef", "kind") != "ClusterIssuer" {
		return errors.New("OpenBao serving certificate is invalid")
	}
	bundle, _ := require("Bundle", "", "openbao-client-ca")
	if nestedString(bundle.Data, "spec", "target", "configMap", "key") != "ca.crt" || !strings.Contains(fmt.Sprint(nested(bundle.Data, "spec", "sources")), "openbao-root-ca") || !strings.Contains(fmt.Sprint(nested(bundle.Data, "spec", "sources")), "tls.crt") {
		return errors.New("OpenBao CA bundle is invalid")
	}
	networkPolicy, _ := require("NetworkPolicy", "openbao", "openbao-ingress")
	if !openBaoNetworkPolicyBoundary(networkPolicy.Data) {
		return errors.New("OpenBao NetworkPolicy is invalid")
	}
	return nil
}

func openBaoReadinessPostRenderCommand(release map[string]any) ([]string, error) {
	renderers, ok := nested(release, "spec", "postRenderers").([]any)
	if !ok || len(renderers) != 1 {
		return nil, errors.New("OpenBao readiness post-renderer is invalid")
	}
	renderer, ok := renderers[0].(map[string]any)
	if !ok || len(renderer) != 1 {
		return nil, errors.New("OpenBao readiness post-renderer is invalid")
	}
	kustomize, ok := renderer["kustomize"].(map[string]any)
	if !ok || len(kustomize) != 1 {
		return nil, errors.New("OpenBao readiness post-renderer is invalid")
	}
	patches, ok := kustomize["patches"].([]any)
	if !ok || len(patches) != 1 {
		return nil, errors.New("OpenBao readiness post-renderer is invalid")
	}
	patch, ok := patches[0].(map[string]any)
	if !ok || len(patch) != 2 {
		return nil, errors.New("OpenBao readiness post-renderer is invalid")
	}
	target, ok := patch["target"].(map[string]any)
	if !ok || len(target) != 4 || stringValue(target["group"]) != "apps" || stringValue(target["version"]) != "v1" || stringValue(target["kind"]) != "StatefulSet" || stringValue(target["name"]) != "openbao" {
		return nil, errors.New("OpenBao readiness post-render target is invalid")
	}
	var operations []struct {
		Operation string   `yaml:"op"`
		Path      string   `yaml:"path"`
		Value     []string `yaml:"value"`
	}
	patchSource := stringValue(patch["patch"])
	if patchSource == "" || strings.Contains(patchSource, "tls-skip-verify") || strings.Contains(patchSource, "BAO_SKIP_VERIFY") || strings.Contains(patchSource, "VAULT_SKIP_VERIFY") {
		return nil, errors.New("OpenBao readiness TLS verification is invalid")
	}
	if err := decodeOne([]byte(patchSource), &operations); err != nil || len(operations) != 1 || operations[0].Operation != "replace" || operations[0].Path != openBaoReadinessPatchPath {
		return nil, errors.New("OpenBao readiness post-render patch is invalid")
	}
	expected := []string{"/bin/sh", "-ec", openBaoReadinessShellCommand}
	if !slices.Equal(operations[0].Value, expected) {
		return nil, errors.New("OpenBao readiness command does not enforce CA and pod DNS verification")
	}
	return slices.Clone(operations[0].Value), nil
}

func platformStoreNamespaceBoundary(store map[string]any) bool {
	conditions, ok := nested(store, "spec", "conditions").([]any)
	if !ok || len(conditions) != 1 {
		return false
	}
	condition, ok := conditions[0].(map[string]any)
	return ok && len(condition) == 1 && exactStringSequence(condition["namespaces"], "external-secrets")
}

func exactStringSequence(value any, expected ...string) bool {
	items, ok := value.([]any)
	if !ok || len(items) != len(expected) {
		return false
	}
	actual := make([]string, 0, len(items))
	for _, item := range items {
		actual = append(actual, stringValue(item))
	}
	return slices.Equal(actual, expected)
}

func exactStringMap(value any, expected map[string]string) bool {
	mapping, ok := value.(map[string]any)
	if !ok || len(mapping) != len(expected) {
		return false
	}
	for key, expectedValue := range expected {
		if stringValue(mapping[key]) != expectedValue {
			return false
		}
	}
	return true
}

func exactMappingKeys(value any, expected ...string) bool {
	mapping, ok := value.(map[string]any)
	if !ok || len(mapping) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, found := mapping[key]; !found {
			return false
		}
	}
	return true
}

func exactTokenRequestRole(role map[string]any, serviceAccount string) bool {
	if nestedString(role, "apiVersion") != "rbac.authorization.k8s.io/v1" {
		return false
	}
	rules, ok := nested(role, "rules").([]any)
	if !ok || len(rules) != 1 {
		return false
	}
	rule, ok := rules[0].(map[string]any)
	return ok && len(rule) == 4 &&
		exactStringSequence(rule["apiGroups"], "") &&
		exactStringSequence(rule["resources"], "serviceaccounts/token") &&
		exactStringSequence(rule["resourceNames"], serviceAccount) &&
		exactStringSequence(rule["verbs"], "create")
}

func exactTokenRequestRoleBinding(binding map[string]any, role, subjectNamespace, subjectName string) bool {
	if nestedString(binding, "apiVersion") != "rbac.authorization.k8s.io/v1" {
		return false
	}
	roleRef, ok := nested(binding, "roleRef").(map[string]any)
	if !ok || len(roleRef) != 3 || stringValue(roleRef["apiGroup"]) != "rbac.authorization.k8s.io" || stringValue(roleRef["kind"]) != "Role" || stringValue(roleRef["name"]) != role {
		return false
	}
	subjects, ok := nested(binding, "subjects").([]any)
	if !ok || len(subjects) != 1 {
		return false
	}
	subject, ok := subjects[0].(map[string]any)
	return ok && len(subject) == 3 && stringValue(subject["kind"]) == "ServiceAccount" && stringValue(subject["namespace"]) == subjectNamespace && stringValue(subject["name"]) == subjectName
}

func exactConsumerSecretStore(store map[string]any) bool {
	if nestedString(store, "apiVersion") != "external-secrets.io/v1" || nestedString(store, "metadata", "annotations", "cloudring.org/non-claim") != "requires-openbao-policy-role-and-live-sync-proof" {
		return false
	}
	provider, ok := nested(store, "spec", "provider").(map[string]any)
	if !ok || len(provider) != 1 {
		return false
	}
	vault, ok := provider["vault"].(map[string]any)
	if !ok || len(vault) != 5 || stringValue(vault["server"]) != "https://openbao-active.openbao.svc:8200" || stringValue(vault["path"]) != "cloudring" || stringValue(vault["version"]) != "v2" {
		return false
	}
	caProvider, ok := vault["caProvider"].(map[string]any)
	if !ok || len(caProvider) != 3 || stringValue(caProvider["type"]) != "ConfigMap" || stringValue(caProvider["name"]) != "openbao-client-ca" || stringValue(caProvider["key"]) != "ca.crt" {
		return false
	}
	auth, ok := vault["auth"].(map[string]any)
	if !ok || len(auth) != 1 {
		return false
	}
	kubernetes, ok := auth["kubernetes"].(map[string]any)
	if !ok || len(kubernetes) != 3 || stringValue(kubernetes["mountPath"]) != "kubernetes-consumer-example" || stringValue(kubernetes["role"]) != "cloudring-consumer-example" {
		return false
	}
	serviceAccountRef, ok := kubernetes["serviceAccountRef"].(map[string]any)
	return ok && len(serviceAccountRef) == 2 && stringValue(serviceAccountRef["name"]) == "cloudring-openbao-reader" && exactStringSequence(serviceAccountRef["audiences"], "openbao")
}

func openBaoNetworkPolicyBoundary(policy map[string]any) bool {
	if !exactSelector(nested(policy, "spec", "podSelector"), map[string]string{
		"app.kubernetes.io/name": "openbao",
		"component":              "server",
	}) || !exactStringSequence(nested(policy, "spec", "policyTypes"), "Ingress") {
		return false
	}
	ingress, ok := nested(policy, "spec", "ingress").([]any)
	if !ok || len(ingress) != 2 {
		return false
	}
	serverRule, ok := ingress[0].(map[string]any)
	if !ok || len(serverRule) != 2 || !exactNetworkPolicyPorts(serverRule["ports"], 8200, 8201) {
		return false
	}
	serverPeers, ok := serverRule["from"].([]any)
	if !ok || len(serverPeers) != 1 {
		return false
	}
	serverPeer, ok := serverPeers[0].(map[string]any)
	if !ok || len(serverPeer) != 1 || !exactSelector(serverPeer["podSelector"], map[string]string{
		"app.kubernetes.io/name": "openbao",
		"component":              "server",
	}) {
		return false
	}
	externalRule, ok := ingress[1].(map[string]any)
	if !ok || len(externalRule) != 2 || !exactNetworkPolicyPorts(externalRule["ports"], 8200) {
		return false
	}
	externalPeers, ok := externalRule["from"].([]any)
	if !ok || len(externalPeers) != 1 {
		return false
	}
	externalPeer, ok := externalPeers[0].(map[string]any)
	return ok && len(externalPeer) == 2 &&
		exactSelector(externalPeer["namespaceSelector"], map[string]string{
			"kubernetes.io/metadata.name": "external-secrets",
		}) && exactSelector(externalPeer["podSelector"], map[string]string{
		"app.kubernetes.io/name":     "external-secrets",
		"app.kubernetes.io/instance": "external-secrets",
	})
}

func exactSelector(value any, expected map[string]string) bool {
	selector, ok := value.(map[string]any)
	if !ok || len(selector) != 1 {
		return false
	}
	labels, ok := selector["matchLabels"].(map[string]any)
	if !ok || len(labels) != len(expected) {
		return false
	}
	for key, expectedValue := range expected {
		if stringValue(labels[key]) != expectedValue {
			return false
		}
	}
	return true
}

func exactNetworkPolicyPorts(value any, expected ...int) bool {
	ports, ok := value.([]any)
	if !ok || len(ports) != len(expected) {
		return false
	}
	for index, expectedPort := range expected {
		port, ok := ports[index].(map[string]any)
		if !ok || len(port) != 2 || stringValue(port["protocol"]) != "TCP" || nestedNumber(port, "port") != expectedPort {
			return false
		}
	}
	return true
}

func validateOpenBaoHCL(source string) error {
	var config openBaoHCL
	if source == "" {
		return errors.New("OpenBao HCL configuration is invalid")
	}
	parsed, err := parseOpenBaoHCL(source)
	if err != nil {
		return errors.New("OpenBao HCL configuration is invalid")
	}
	config = parsed
	if config.UI || len(config.Listeners) != 1 || len(config.Storage) != 1 || len(config.ServiceRegistrations) != 1 || config.ServiceRegistrations[0].Type != "kubernetes" {
		return errors.New("OpenBao HCL block inventory is invalid")
	}
	if len(config.Audits) != 1 {
		return errors.New("OpenBao persistent audit configuration is invalid")
	}
	audit := config.Audits[0]
	if audit.Type != "file" || audit.Name != "persistent" || audit.Description != "CloudRING persistent audit" || audit.Options.FilePath != "/openbao/audit/audit.log" || audit.Options.Mode != "0600" || audit.Options.LogRaw != "false" {
		return errors.New("OpenBao persistent audit configuration is invalid")
	}
	listener := config.Listeners[0]
	if listener.Type != "tcp" || listener.Address != "[::]:8200" || listener.ClusterAddress != "[::]:8201" || listener.TLSDisable != 0 || listener.TLSCertFile != "/openbao/tls/server/tls.crt" || listener.TLSKeyFile != "/openbao/tls/server/tls.key" || listener.TLSClientCAFile != "/openbao/tls/client/ca.crt" {
		return errors.New("OpenBao listener TLS configuration is invalid")
	}
	storage := config.Storage[0]
	if storage.Type != "raft" || storage.Path != "/openbao/data" || len(storage.RetryJoin) != 3 {
		return errors.New("OpenBao Raft storage configuration is invalid")
	}
	expectedAddresses := map[string]bool{
		"https://openbao-0.openbao-internal.openbao.svc:8200": true,
		"https://openbao-1.openbao-internal.openbao.svc:8200": true,
		"https://openbao-2.openbao-internal.openbao.svc:8200": true,
	}
	for _, join := range storage.RetryJoin {
		if !expectedAddresses[join.LeaderAPIAddress] || join.LeaderCACertFile != "/openbao/tls/client/ca.crt" || join.LeaderClientCertFile != "/openbao/tls/server/tls.crt" || join.LeaderClientKeyFile != "/openbao/tls/server/tls.key" || join.LeaderTLSServerName != "openbao.openbao.svc" {
			return errors.New("OpenBao Raft retry-join TLS configuration is invalid")
		}
		delete(expectedAddresses, join.LeaderAPIAddress)
	}
	if len(expectedAddresses) != 0 {
		return errors.New("OpenBao Raft retry-join set is incomplete")
	}
	return nil
}

func nested(root map[string]any, path ...string) any {
	var value any = root
	for _, key := range path {
		mapping, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = mapping[key]
	}
	return value
}

func nestedString(root map[string]any, path ...string) string {
	return stringValue(nested(root, path...))
}
func nestedBool(root map[string]any, path ...string) bool {
	value, _ := nested(root, path...).(bool)
	return value
}
func nestedNumber(root map[string]any, path ...string) int {
	switch value := nested(root, path...).(type) {
	case int:
		return value
	case int64:
		return int(value)
	default:
		return 0
	}
}
func stringValue(value any) string {
	text, _ := value.(string)
	return text
}
func digestTagged(value string) bool {
	parts := strings.Split(value, "@sha256:")
	return len(parts) == 2 && parts[0] != "" && len(parts[1]) == 64
}
