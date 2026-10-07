// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package ocs

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func Test_SyntheticConnectorPackageReference_validates(t *testing.T) {
	raw, err := os.ReadFile("../../reference/synthetic-service/module-package.json")
	if err != nil {
		t.Fatalf("read synthetic connector package reference: %v", err)
	}
	var pkg ConnectorPackage
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatalf("unmarshal synthetic connector package reference: %v", err)
	}
	if err := pkg.Validate(); err != nil {
		t.Fatalf("expected synthetic connector package to validate: %v", err)
	}
}

func Test_SyntheticInvalidImplementationReference_is_rejected(t *testing.T) {
	raw, err := os.ReadFile("testdata/invalid-implementation-reference.json")
	if err != nil {
		t.Fatalf("read invalid implementation-reference fixture: %v", err)
	}
	var pkg ConnectorPackage
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatalf("unmarshal invalid implementation-reference fixture: %v", err)
	}

	err = pkg.Validate()
	if err == nil {
		t.Fatal("expected implementation-specific dependency reference to fail")
	}
	want := "class=coupling owner=service path=service.spec.dependencies[0].implementationRef"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected %q in validation error %q", want, err.Error())
	}
}
