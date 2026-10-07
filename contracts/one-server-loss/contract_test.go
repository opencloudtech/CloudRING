// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package oneserverlosscontract_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/resilience/oneserverloss"
)

func TestContractsAreStrictAndSyntheticRequestMatchesRuntimeShape(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"request.schema.json", "ready-marker.schema.json", "probe-protocol.schema.json", "receipt.schema.json"} {
		// #nosec G304 -- repository-owned closed schema list.
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if strictjson.Decode(payload, &schema) != nil || schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
			t.Fatalf("%s is not a strict draft-2020-12 schema", path)
		}
		if _, err := jsonschema.NewCompiler().Compile(path); err != nil {
			t.Fatalf("compile %s: %v", path, err)
		}
	}
	schema, err := jsonschema.NewCompiler().Compile("request.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile("fixtures/synthetic-request.json") // #nosec G304 -- repository-owned fixture.
	if err != nil {
		t.Fatal(err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil || schema.Validate(instance) != nil {
		t.Fatalf("synthetic request does not match schema: %v", err)
	}
	var request oneserverloss.Request
	if strictjson.DecodeExact(payload, &request) != nil || request.SchemaVersion != oneserverloss.RequestSchemaVersion || len(request.Workloads) != 1 || !request.VM.RequirePreLossOnTarget {
		t.Fatal("synthetic request does not match the runtime request shape")
	}
}
