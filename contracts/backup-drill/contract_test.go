// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package backupdrill_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/backup/drill"
)

func TestBackupDrillContractsCompileAndRemainClosed(t *testing.T) {
	t.Parallel()
	paths := []string{"plan.schema.json", "approval.schema.json", "adapter-request.schema.json", "adapter-response.schema.json", "journal-entry.schema.json", "execution-receipt.schema.json"}
	for _, path := range paths {
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

func TestSyntheticPlanMatchesSchemaAndRuntime(t *testing.T) {
	t.Parallel()
	payload, err := os.ReadFile("fixtures/synthetic-plan.json") // #nosec G304 -- repository-owned source-safe fixture.
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.NewCompiler().Compile("plan.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil || schema.Validate(instance) != nil {
		t.Fatalf("synthetic plan does not match schema: %v", err)
	}
	var plan drill.Plan
	if err := strictjson.DecodeExact(payload, &plan); err != nil || drill.ValidatePlan(plan) != nil {
		t.Fatalf("synthetic plan does not match runtime: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(payload, &generic); err != nil {
		t.Fatal(err)
	}
	generic["unknown"] = true
	unknown, _ := json.Marshal(generic)
	if strictjson.DecodeExact(unknown, &plan) == nil {
		t.Fatal("runtime accepted unknown plan field")
	}
	duplicate := bytes.Replace(payload, []byte(`"operationId":`), []byte(`"operationId":"duplicate","operationId":`), 1)
	if strictjson.DecodeExact(duplicate, &plan) == nil {
		t.Fatal("runtime accepted duplicate plan field")
	}
}

func TestNegativeSchemaCasesMatchRuntime(t *testing.T) {
	t.Parallel()
	base, err := os.ReadFile("fixtures/synthetic-plan.json") // #nosec G304 -- repository-owned source-safe fixture.
	if err != nil {
		t.Fatal(err)
	}
	vectorsPayload, err := os.ReadFile("fixtures/negative-schema-cases.json") // #nosec G304 -- repository-owned negative vectors.
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		SchemaVersion string `json:"schemaVersion"`
		PlanCases     []struct {
			Name  string `json:"name"`
			Path  string `json:"path"`
			Value any    `json:"value"`
		} `json:"planCases"`
		InvalidEvidenceRefs []string `json:"invalidEvidenceRefs"`
	}
	if err := strictjson.DecodeExact(vectorsPayload, &vectors); err != nil || vectors.SchemaVersion != "cloudring.backup-drill.negative-schema-cases/v1" {
		t.Fatalf("invalid negative schema vectors: %v", err)
	}
	planSchema, err := jsonschema.NewCompiler().Compile("plan.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range vectors.PlanCases {
		t.Run(test.Name, func(t *testing.T) {
			var document any
			if err := json.Unmarshal(base, &document); err != nil {
				t.Fatal(err)
			}
			if err := setJSONPath(document, strings.Split(test.Path, "/"), test.Value); err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			if planSchema.Validate(instance) == nil {
				t.Fatal("plan schema accepted negative conformance vector")
			}
			var plan drill.Plan
			if decodeErr := strictjson.DecodeExact(payload, &plan); decodeErr == nil && drill.ValidatePlan(plan) == nil {
				t.Fatal("runtime accepted negative schema conformance vector")
			}
		})
	}
	evidenceSchema, err := jsonschema.NewCompiler().Compile("adapter-response.schema.json#/$defs/evidence")
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range vectors.InvalidEvidenceRefs {
		instance, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"ref":` + strconv.Quote(reference) + `,"sha256":"` + strings.Repeat("a", 64) + `"}`))
		if err != nil {
			t.Fatal(err)
		}
		if evidenceSchema.Validate(instance) == nil {
			t.Fatalf("evidence schema accepted unsafe ref %q", reference)
		}
	}
}

func setJSONPath(value any, path []string, replacement any) error {
	if len(path) == 0 {
		return nil
	}
	if len(path) == 1 {
		object, ok := value.(map[string]any)
		if !ok {
			return strconv.ErrSyntax
		}
		object[path[0]] = replacement
		return nil
	}
	switch current := value.(type) {
	case map[string]any:
		return setJSONPath(current[path[0]], path[1:], replacement)
	case []any:
		index, err := strconv.Atoi(path[0])
		if err != nil || index < 0 || index >= len(current) {
			return strconv.ErrSyntax
		}
		return setJSONPath(current[index], path[1:], replacement)
	default:
		return strconv.ErrSyntax
	}
}
