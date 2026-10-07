// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package privateartifact

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type exactFixture struct {
	Known string `json:"known"`
}

func TestReadJSONReadsExactOwnerOnlyArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(`{"known":"value"}`), 0o600); err != nil {
		t.Fatalf("write input fixture: %v", err)
	}
	var destination exactFixture
	err := ReadJSON(path, &destination)
	if runtime.GOOS == "windows" {
		if err == nil {
			t.Fatal("ReadJSON claimed protected native Windows reads")
		}
		return
	}
	if err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if destination.Known != "value" {
		t.Fatalf("decoded value = %q, want value", destination.Known)
	}
}

func TestReadJSONRejectsUnknownFields(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("protected reads intentionally fail closed on native Windows")
	}
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(`{"known":"value","unknown":true}`), 0o600); err != nil {
		t.Fatalf("write input fixture: %v", err)
	}
	var destination exactFixture
	if err := ReadJSON(path, &destination); err == nil {
		t.Fatal("ReadJSON accepted an unknown JSON field")
	}
}
