// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package registry

import (
	"os"
	"strings"
	"testing"
)

func TestParseSyntheticRegistry(t *testing.T) {
	registry := parseFixture(t, "../../contracts/module-registry/fixtures/synthetic-module-registry.json")
	if registry.RegistryID != "synthetic-core-modules" || len(registry.Modules) != 2 || len(registry.PlanRequests) != 2 {
		t.Fatalf("unexpected registry summary: id=%q modules=%d plans=%d", registry.RegistryID, len(registry.Modules), len(registry.PlanRequests))
	}
	if registry.Modules[1].Dependencies[0].ModuleID != "network-foundation" {
		t.Fatalf("dependency was not retained: %#v", registry.Modules[1].Dependencies)
	}
}

func TestParseSyntheticNegativeFixtures(t *testing.T) {
	for _, path := range []string{
		"../../contracts/module-registry/fixtures/invalid-duplicate-module-id.json",
		"../../contracts/module-registry/fixtures/invalid-missing-rollback-evidence.json",
		"../../contracts/module-registry/fixtures/invalid-service-implementation-reference.json",
	} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path) // #nosec G304 -- path comes from the repository-controlled fixture table.
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if _, err := Parse(data); err == nil {
				t.Fatalf("fixture unexpectedly passed validation")
			}
		})
	}
}

func TestValidateRejectsCycleAndImplementationReference(t *testing.T) {
	registry := parseFixture(t, "../../contracts/module-registry/fixtures/synthetic-module-registry.json")
	registry.Modules[0].Dependencies = []Dependency{{ModuleID: registry.Modules[1].ID, State: "installed"}}
	if err := registry.Validate(); err == nil || !strings.Contains(err.Error(), "code=dependency.cycle") {
		t.Fatalf("cycle error = %v", err)
	}

	registry = parseFixture(t, "../../contracts/module-registry/fixtures/synthetic-module-registry.json")
	refs := []string{"internal/controller"}
	registry.Modules[0].ServiceImplementationRefs = &refs
	if err := registry.Validate(); err == nil || !strings.Contains(err.Error(), "code=module.implementation-reference") {
		t.Fatalf("implementation reference error = %v", err)
	}
}

func TestParseRejectsUnknownAndTrailingJSON(t *testing.T) {
	data, err := os.ReadFile("../../contracts/module-registry/fixtures/synthetic-module-registry.json") // #nosec G304 -- repository-controlled test fixture.
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	unknown := append([]byte(`{"unexpected":true}`), data[1:]...)
	if _, err := Parse(unknown); err == nil {
		t.Fatal("unknown property unexpectedly passed")
	}
	trailing := append(append([]byte{}, data...), []byte(` {}`)...)
	if _, err := Parse(trailing); err == nil {
		t.Fatal("trailing JSON unexpectedly passed")
	}
}

func parseFixture(t *testing.T, path string) Registry {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from the repository-controlled fixture call site.
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	registry, err := Parse(data)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return registry
}
