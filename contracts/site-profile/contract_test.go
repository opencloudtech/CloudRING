// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package siteprofilecontract

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

func TestExampleConformsToMachineReadableSchema(t *testing.T) {
	schema, err := jsonschema.NewCompiler().Compile("provider-site-profile.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	encoded := exampleJSON(t)
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("example does not conform: %v", err)
	}
}

func TestSchemaRejectsReadinessOverclaim(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal(exampleJSON(t), &document); err != nil {
		t.Fatal(err)
	}
	document["spec"].(map[string]any)["nonClaim"] = "production-ready"
	if schemaAccepts(t, document) {
		t.Fatal("readiness overclaim passed schema validation")
	}
}

func TestSchemaRejectsDNSRoundRobinOnlyPublicIngress(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal(exampleJSON(t), &document); err != nil {
		t.Fatal(err)
	}
	network := document["spec"].(map[string]any)["network"].(map[string]any)
	network["publicIngressHA"].(map[string]any)["mode"] = "dns-round-robin"
	if schemaAccepts(t, document) {
		t.Fatal("DNS round robin over node addresses passed HA ingress validation")
	}
}

func TestSchemaRequiresControlPlaneAPIHA(t *testing.T) {
	for _, field := range []string{
		"mode",
		"endpointRef",
		"ipv4AddressRef",
		"ipv6AddressRef",
		"servingCertificateSANRefs",
		"cniBootstrapEndpointRef",
		"controlPlaneTransportDeviceRef",
		"cniDeviceRefs",
		"healthCheckRef",
		"failoverPolicyRef",
		"servingCertificateLifecycle",
	} {
		t.Run(field, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(exampleJSON(t), &document); err != nil {
				t.Fatal(err)
			}
			ha := document["spec"].(map[string]any)["network"].(map[string]any)["controlPlaneAPIHA"].(map[string]any)
			delete(ha, field)
			if schemaAccepts(t, document) {
				t.Fatalf("control-plane API HA without %s passed schema validation", field)
			}
		})
	}
}

func TestSchemaRequiresServingCertificateLifecycle(t *testing.T) {
	for _, field := range []string{"rolloutStrategy", "reconfigurationPlanRef", "rollbackPlanRef", "oneServerLossAcceptanceRef"} {
		t.Run(field, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(exampleJSON(t), &document); err != nil {
				t.Fatal(err)
			}
			lifecycle := document["spec"].(map[string]any)["network"].(map[string]any)["controlPlaneAPIHA"].(map[string]any)["servingCertificateLifecycle"].(map[string]any)
			delete(lifecycle, field)
			if schemaAccepts(t, document) {
				t.Fatalf("serving-certificate lifecycle without %s passed schema validation", field)
			}
		})
	}
}

func TestSchemaRejectsDuplicateControlPlaneLists(t *testing.T) {
	for _, field := range []string{"servingCertificateSANRefs", "cniDeviceRefs"} {
		t.Run(field, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(exampleJSON(t), &document); err != nil {
				t.Fatal(err)
			}
			ha := document["spec"].(map[string]any)["network"].(map[string]any)["controlPlaneAPIHA"].(map[string]any)
			values := ha[field].([]any)
			ha[field] = append(values, values[0])
			if schemaAccepts(t, document) {
				t.Fatalf("duplicate %s passed schema validation", field)
			}
		})
	}
}

func TestSchemaRejectsDNSRoundRobinControlPlaneAPI(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal(exampleJSON(t), &document); err != nil {
		t.Fatal(err)
	}
	network := document["spec"].(map[string]any)["network"].(map[string]any)
	network["controlPlaneAPIHA"].(map[string]any)["mode"] = "dns-round-robin"
	if schemaAccepts(t, document) {
		t.Fatal("DNS round robin over control-plane nodes passed API HA validation")
	}
}

func TestSchemaRequiresDualStackIngressAddressesAndFailover(t *testing.T) {
	for _, field := range []string{"ipv4AddressRef", "ipv6AddressRef", "healthCheckRef", "failoverPolicyRef"} {
		t.Run(field, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(exampleJSON(t), &document); err != nil {
				t.Fatal(err)
			}
			ha := document["spec"].(map[string]any)["network"].(map[string]any)["publicIngressHA"].(map[string]any)
			delete(ha, field)
			if schemaAccepts(t, document) {
				t.Fatalf("HA ingress without %s passed schema validation", field)
			}
		})
	}
}

func TestSchemaRequiresDurableHostRuntimeCapacity(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal(exampleJSON(t), &document); err != nil {
		t.Fatal(err)
	}
	baseline := document["spec"].(map[string]any)["hostRuntimeBaseline"].(map[string]any)
	baseline["inotifyMaxUserInstances"] = float64(128)
	if schemaAccepts(t, document) {
		t.Fatal("host runtime baseline below 1024 inotify instances passed schema validation")
	}
}

func TestSchemaRequiresHostRuntimePersistenceAndVerificationRefs(t *testing.T) {
	for _, field := range []string{"persistenceRef", "verificationRef"} {
		t.Run(field, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(exampleJSON(t), &document); err != nil {
				t.Fatal(err)
			}
			baseline := document["spec"].(map[string]any)["hostRuntimeBaseline"].(map[string]any)
			delete(baseline, field)
			if schemaAccepts(t, document) {
				t.Fatalf("host runtime baseline without %s passed schema validation", field)
			}
		})
	}
}

func TestSchemaRejectsInventoryWithoutBaselineControlPlaneAndWorkerRoles(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal(exampleJSON(t), &document); err != nil {
		t.Fatal(err)
	}
	nodes := document["spec"].(map[string]any)["inventory"].(map[string]any)["nodes"].([]any)
	for _, rawNode := range nodes {
		rawNode.(map[string]any)["roles"] = []any{"gateway"}
	}
	if schemaAccepts(t, document) {
		t.Fatal("gateway-only inventory passed baseline role validation")
	}
}

func TestSchemaRejectsInventoryWithoutThreeGatewayNodes(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal(exampleJSON(t), &document); err != nil {
		t.Fatal(err)
	}
	nodes := document["spec"].(map[string]any)["inventory"].(map[string]any)["nodes"].([]any)
	nodes[2].(map[string]any)["roles"] = []any{"control-plane", "worker"}
	if schemaAccepts(t, document) {
		t.Fatal("two-node Gateway inventory passed schema validation")
	}
}

func schemaAccepts(t *testing.T, document any) bool {
	t.Helper()
	schema, err := jsonschema.NewCompiler().Compile("provider-site-profile.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	return schema.Validate(instance) == nil
}

func exampleJSON(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "examples", "provider-site-profile.yaml")
	// #nosec G304 -- the test reads the repository-owned example at a fixed relative path.
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
