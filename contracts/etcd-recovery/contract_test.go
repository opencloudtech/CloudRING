// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package etcdrecoverycontract_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/backup/etcdrecovery"
)

func TestRecoveryContractsCompileAndRemainClosed(t *testing.T) {
	for _, path := range []string{
		"request.schema.json",
		"receipt.schema.json",
		"input-secret-projection.schema.json",
		"image-identity.schema.json",
	} {
		data, err := os.ReadFile(path) // #nosec G304 -- closed repository-owned schema list.
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := strictjson.Decode(data, &document); err != nil || document["$schema"] != "https://json-schema.org/draft/2020-12/schema" || document["additionalProperties"] != false {
			t.Fatalf("%s is not a strict draft 2020-12 schema: %v", path, err)
		}
		if _, err := jsonschema.NewCompiler().Compile(path); err != nil {
			t.Fatalf("compile %s: %v", path, err)
		}
	}
}

func TestCanonicalRuntimeDocumentsMatchPublicSchemas(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	projection := validProjection()
	projectionPayload, err := etcdrecovery.CanonicalInputSecretProjection(projection)
	if err != nil {
		t.Fatal(err)
	}
	assertSchemaAccepts(t, "input-secret-projection.schema.json", projectionPayload)

	request := validLocalRequest(t, now, projection)
	requestPayload, err := etcdrecovery.CanonicalRequest(request, now)
	if err != nil {
		t.Fatal(err)
	}
	assertSchemaAccepts(t, "request.schema.json", requestPayload)

	receiptPayload, err := etcdrecovery.CanonicalReceipt(etcdrecovery.InitializationFailureReceipt(now))
	if err != nil {
		t.Fatal(err)
	}
	assertSchemaAccepts(t, "receipt.schema.json", receiptPayload)

	identity := validImageIdentity()
	identityPayload, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	assertSchemaAccepts(t, "image-identity.schema.json", identityPayload)
}

func TestRuntimeAndSchemasRejectTheSameUnsafeContractSurfaces(t *testing.T) {
	t.Run("input projection", func(t *testing.T) {
		projection := validProjection()
		projection.ProjectedObjectName = strings.Repeat("a", 64) + ".request"
		if _, err := etcdrecovery.CanonicalInputSecretProjection(projection); err == nil {
			t.Fatal("runtime accepted an overlong DNS label")
		}
		assertSchemaRejects(t, "input-secret-projection.schema.json", mustJSON(t, projection))
	})

	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	base := validS3Request(t, now, validProjection())
	for _, test := range []struct {
		name   string
		mutate func(*etcdrecovery.Request)
	}{
		{name: "endpoint path", mutate: func(value *etcdrecovery.Request) { value.Endpoint += "/private" }},
		{name: "uppercase endpoint", mutate: func(value *etcdrecovery.Request) { value.Endpoint = "https://Objects.example.test" }},
		{name: "invalid region", mutate: func(value *etcdrecovery.Request) { value.Region = ".private" }},
		{name: "short bucket", mutate: func(value *etcdrecovery.Request) { value.Bucket = "ab" }},
		{name: "object traversal", mutate: func(value *etcdrecovery.Request) { value.ObjectKey = "snapshots/../private.db" }},
		{name: "tool digest", mutate: func(value *etcdrecovery.Request) { value.EtcdutlSHA256 = strings.Repeat("f", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.mutate(&candidate)
			candidate.ObjectIdentitySHA256 = etcdrecovery.ObjectIdentitySHA256(candidate)
			if _, err := etcdrecovery.CanonicalRequest(candidate, now); err == nil {
				t.Fatal("runtime accepted unsafe request")
			}
			assertSchemaRejects(t, "request.schema.json", mustJSON(t, candidate))
		})
	}

	t.Run("local raw source reference", func(t *testing.T) {
		candidate := validLocalRequest(t, now, validProjection())
		candidate.ObjectKey = "private.db"
		candidate.ObjectIdentitySHA256 = etcdrecovery.ObjectIdentitySHA256(candidate)
		if _, err := etcdrecovery.CanonicalRequest(candidate, now); err == nil {
			t.Fatal("runtime accepted a raw reference in local mode")
		}
		assertSchemaRejects(t, "request.schema.json", mustJSON(t, candidate))
	})
}

func TestReceiptSchemaRejectsImpossibleBindingsAndStatusTuples(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	payload, err := etcdrecovery.CanonicalReceipt(etcdrecovery.InitializationFailureReceipt(now))
	if err != nil {
		t.Fatal(err)
	}
	var base map[string]any
	if err := json.Unmarshal(payload, &base); err != nil {
		t.Fatal(err)
	}

	invalidTuple := cloneDocument(t, base)
	invalidTuple["status"] = "timeout"
	invalidTuple["reasonCode"] = "operation_cancelled"
	assertSchemaRejects(t, "receipt.schema.json", mustJSON(t, invalidTuple))

	successFieldOnFailure := cloneDocument(t, base)
	successFieldOnFailure["sourceKvHashSha256"] = strings.Repeat("a", 64)
	assertSchemaRejects(t, "receipt.schema.json", mustJSON(t, successFieldOnFailure))

	partialBinding := cloneDocument(t, base)
	partialBinding["sourceMode"] = "local-file"
	assertSchemaRejects(t, "receipt.schema.json", mustJSON(t, partialBinding))

	completeWithoutRequestDigest := cloneDocument(t, base)
	delete(completeWithoutRequestDigest, "requestSha256")
	for key, value := range map[string]any{
		"sourceMode":             "local-file",
		"snapshotIdSha256":       strings.Repeat("1", 64),
		"snapshotChecksumSha256": strings.Repeat("2", 64),
		"snapshotBytes":          4096,
		"endpointSha256":         strings.Repeat("3", 64),
		"objectReferenceSha256":  strings.Repeat("4", 64),
		"objectIdentitySha256":   strings.Repeat("5", 64),
		"clusterIdentitySha256":  strings.Repeat("6", 64),
		"jobTemplateSha256":      strings.Repeat("7", 64),
		"executionProfileSha256": strings.Repeat("8", 64),
		"inputSecretSha256":      strings.Repeat("9", 64),
		"workerImageDigest":      "sha256:" + strings.Repeat("a", 64),
	} {
		completeWithoutRequestDigest[key] = value
	}
	assertSchemaRejects(t, "receipt.schema.json", mustJSON(t, completeWithoutRequestDigest))
}

func TestKubernetesTemplateKeepsWorkerUnprivilegedAndUnpublished(t *testing.T) {
	payload, err := os.ReadFile("kubernetes-job.template.yaml") // #nosec G304 -- repository-owned template.
	if err != nil {
		t.Fatal(err)
	}
	required := [][]byte{
		[]byte("automountServiceAccountToken: false"), []byte("runAsNonRoot: true"),
		[]byte("readOnlyRootFilesystem: true"), []byte("allowPrivilegeEscalation: false"),
		[]byte("drop: [ALL]"), []byte("terminationMessagePath: /work/output/receipt.json"),
		[]byte("REPLACE_WITH_PUBLISHED_DIGEST"), []byte("activeDeadlineSeconds: 1860"),
		[]byte("cidr: 192.0.2.0/32"),
	}
	for _, value := range required {
		if !bytes.Contains(payload, value) {
			t.Fatalf("Kubernetes template lacks %q", value)
		}
	}
	for _, forbidden := range []string{
		"latest",
		"automountServiceAccountToken: true",
		"privileged: true",
		"hostNetwork: true",
		"activeDeadlineSeconds: 1800",
		"    - ports:\n        - {protocol: TCP, port: 443}",
	} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("Kubernetes template contains forbidden value %q", forbidden)
		}
	}
}

func TestExternalSecretTemplateUsesExplicitImmutableCredentialKeys(t *testing.T) {
	payload, err := os.ReadFile("external-secret.template.yaml") // #nosec G304 -- repository-owned template.
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"refreshPolicy: CreatedOnce",
		"secretKey: access-key-id",
		"secretKey: secret-access-key",
		"REPLACE_WITH_REVIEWED_ACCESS_KEY_REFERENCE",
		"REPLACE_WITH_REVIEWED_SECRET_KEY_REFERENCE",
	} {
		if !strings.Contains(string(payload), required) {
			t.Fatalf("ExternalSecret template lacks %q", required)
		}
	}
	for _, forbidden := range []string{"dataFrom:", "extract:", "refreshInterval:"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("ExternalSecret template contains broad or mutable value %q", forbidden)
		}
	}
}

func validProjection() etcdrecovery.InputSecretProjection {
	return etcdrecovery.InputSecretProjection{
		SchemaVersion:       etcdrecovery.InputProjectionSchemaVersion,
		Namespace:           "kube-system",
		ProjectedObjectName: "cloudring-etcd-recovery-request",
		SecretKey:           "request.json",
		MountPath:           etcdrecovery.DefaultRequestPath,
		DefaultMode:         0o440,
		Optional:            false,
		ReadOnly:            true,
	}
}

func validLocalRequest(t *testing.T, now time.Time, projection etcdrecovery.InputSecretProjection) etcdrecovery.Request {
	t.Helper()
	inputSecretSHA256, err := etcdrecovery.InputSecretProjectionSHA256(projection)
	if err != nil {
		t.Fatal(err)
	}
	request := etcdrecovery.Request{
		SchemaVersion:          etcdrecovery.RequestSchemaVersion,
		OperationID:            "operation-01",
		SnapshotID:             "snapshot-01",
		SnapshotChecksumSHA256: strings.Repeat("1", 64),
		SnapshotBytes:          4096,
		SourceMode:             "local-file",
		ClusterIdentitySHA256:  strings.Repeat("2", 64),
		JobTemplateSHA256:      strings.Repeat("3", 64),
		ExecutionProfileSHA256: strings.Repeat("4", 64),
		InputSecretSHA256:      inputSecretSHA256,
		WorkerExecutableSHA256: strings.Repeat("5", 64),
		WorkerImageDigest:      "sha256:" + strings.Repeat("6", 64),
		EtcdutlVersion:         etcdrecovery.ToolVersion,
		EtcdutlSHA256:          etcdrecovery.ToolSHA256,
		IssuedAt:               now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt:              now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		TimeoutSeconds:         600,
	}
	request.ObjectIdentitySHA256 = etcdrecovery.ObjectIdentitySHA256(request)
	return request
}

func validS3Request(t *testing.T, now time.Time, projection etcdrecovery.InputSecretProjection) etcdrecovery.Request {
	t.Helper()
	request := validLocalRequest(t, now, projection)
	request.SourceMode = "s3"
	request.Endpoint = "https://objects.example.test"
	request.Region = "eu-west-1"
	request.Bucket = "synthetic-backup"
	request.ObjectKey = "snapshots/synthetic.db"
	request.ObjectVersion = "version-01"
	request.ObjectIdentitySHA256 = etcdrecovery.ObjectIdentitySHA256(request)
	if _, err := etcdrecovery.CanonicalRequest(request, now); err != nil {
		t.Fatalf("valid S3 fixture: %v", err)
	}
	return request
}

func validImageIdentity() map[string]any {
	return map[string]any{
		"schemaVersion":          etcdrecovery.ImageIdentitySchemaVersion,
		"sourceRepository":       "https://github.com/opencloudtech/CloudRING",
		"sourceCommitSha":        strings.Repeat("1", 40),
		"sourceDateEpoch":        1784793600,
		"buildPlatform":          "linux/amd64",
		"imageName":              "ghcr.io/opencloudtech/cloudring-etcd-recovery-worker",
		"imageDigest":            "sha256:" + strings.Repeat("2", 64),
		"imageSubjectDigest":     "sha256:" + strings.Repeat("3", 64),
		"workerExecutableSha256": strings.Repeat("4", 64),
		"etcdutlVersion":         etcdrecovery.ToolVersion,
		"etcdutlSha256":          etcdrecovery.ToolSHA256,
		"baseImageName":          "gcr.io/distroless/static-debian12:nonroot",
		"baseImageDigest":        "sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35",
		"containerfileSha256":    strings.Repeat("5", 64),
		"componentSbomSha256":    strings.Repeat("6", 64),
		"imageSbomSha256":        strings.Repeat("7", 64),
	}
}

func assertSchemaAccepts(t *testing.T, path string, payload []byte) {
	t.Helper()
	if err := validateSchemaPayload(t, path, payload); err != nil {
		t.Fatalf("%s rejected valid canonical payload: %v", path, err)
	}
}

func assertSchemaRejects(t *testing.T, path string, payload []byte) {
	t.Helper()
	if err := validateSchemaPayload(t, path, payload); err == nil {
		t.Fatalf("%s accepted unsafe payload: %s", path, payload)
	}
}

func validateSchemaPayload(t *testing.T, path string, payload []byte) error {
	t.Helper()
	schema, err := jsonschema.NewCompiler().Compile(path)
	if err != nil {
		t.Fatalf("compile %s: %v", path, err)
	}
	var document any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode schema fixture: %v", err)
	}
	return schema.Validate(document)
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func cloneDocument(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	payload := mustJSON(t, value)
	var cloned map[string]any
	if err := json.Unmarshal(payload, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}
