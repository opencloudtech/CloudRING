// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRunValidatesAndRedactsInputPath(t *testing.T) {
	data, err := os.ReadFile("../../contracts/module-registry/fixtures/synthetic-module-registry.json") // #nosec G703 G304 -- repository-controlled test fixture.
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	path := t.TempDir() + "/private-registry.json"
	if err := os.WriteFile(path, data, 0o600); err != nil { // #nosec G703 -- test writes only inside t.TempDir.
		t.Fatalf("write fixture: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"validate", path}, &stdout, &stderr); code != exitPassed {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"passed":true`) || strings.Contains(stdout.String(), path) || stderr.Len() != 0 {
		t.Fatalf("unexpected sanitized output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunReturnsStableUsageAndBlockedCodes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"validate"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("usage exit=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"validate", "does-not-exist.json"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("missing input exit=%d", code)
	}
	path := t.TempDir() + "/invalid.json"
	if err := os.WriteFile(path, []byte(`{"schemaVersion":"cloudring.module-registry/v1"}`), 0o600); err != nil {
		t.Fatalf("write invalid fixture: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"validate", path}, &stdout, &stderr); code != exitBlocked || strings.Contains(stderr.String(), path) {
		t.Fatalf("blocked exit=%d stderr=%q", code, stderr.String())
	}
}
