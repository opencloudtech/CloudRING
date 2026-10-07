// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package ocsv3_test

import (
	"os"
	"strings"
	"testing"

	"github.com/opencloudtech/CloudRING/sdk/ocsv3"
)

func TestParseConnectorPackage_accepts_public_synthetic_fixture(t *testing.T) {
	raw := readFixture(t, "../../reference/synthetic-service/module-package.json")

	pkg, err := ocsv3.ParseConnectorPackage(raw)
	if err != nil {
		t.Fatalf("parse synthetic module package: %v", err)
	}
	if pkg.APIVersion != ocsv3.APIVersion {
		t.Fatalf("apiVersion = %q, want %q", pkg.APIVersion, ocsv3.APIVersion)
	}
	if pkg.Metadata.Name != "synthetic-service-module-package" {
		t.Fatalf("metadata.name = %q", pkg.Metadata.Name)
	}
}

func TestParseConnectorPackage_rejects_malformed_json(t *testing.T) {
	_, err := ocsv3.ParseConnectorPackage([]byte(`{"kind":`))
	if err == nil {
		t.Fatal("expected malformed JSON to fail")
	}
	if !strings.Contains(err.Error(), "parse connector package") {
		t.Fatalf("expected parse context, got %q", err.Error())
	}
}

func TestValidateConnectorPackageBytes_accepts_public_synthetic_fixture(t *testing.T) {
	raw := readFixture(t, "../../reference/synthetic-service/module-package.json")

	if err := ocsv3.ValidateConnectorPackageBytes(raw); err != nil {
		t.Fatalf("validate synthetic module package: %v", err)
	}
}

func TestValidateConnectorPackageBytes_rejects_implementation_specific_reference(t *testing.T) {
	raw := readFixture(t, "../../pkg/ocs/testdata/invalid-implementation-reference.json")

	err := ocsv3.ValidateConnectorPackageBytes(raw)
	if err == nil {
		t.Fatal("expected implementation-specific dependency reference to fail")
	}
	for _, want := range []string{
		"validate connector package",
		"class=coupling owner=service path=service.spec.dependencies[0].implementationRef",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- tests pass only repository fixtures selected by the test itself.
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return raw
}
