//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/backup/drill"
	"github.com/opencloudtech/CloudRING/pkg/backup/velero118"
	"github.com/opencloudtech/CloudRING/pkg/secureexec"
)

func TestNewCollectorKubectlReaderRejectsStdioDescriptor(t *testing.T) {
	if _, err := newCollectorKubectlReader("kubectl", 2); err == nil {
		t.Fatal("stdio kubeconfig descriptor must fail closed")
	}
}

func TestValidateDrillToolIdentityPinsCurrentExecutable(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := secureexec.PinAbsolute(path, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	digest := pinned.IdentitySHA256()
	if err := pinned.Close(); err != nil {
		t.Fatal(err)
	}
	plan := drill.Plan{Tool: drill.ExecutableIdentity{Name: "cloudring-backup", ExecutableSHA256: digest}}
	if err := validateDrillToolIdentity(plan); err != nil {
		t.Fatal(err)
	}
	plan.Tool.ExecutableSHA256 = strings.Repeat("f", 64)
	if err := validateDrillToolIdentity(plan); err == nil {
		t.Fatal("changed backup drill tool digest accepted")
	}
}

func TestBaselineWritesPrivateNonOverwritingArtifact(t *testing.T) {
	directory := t.TempDir()
	requestPath := filepath.Join(directory, "request.json")
	outputPath := filepath.Join(directory, "baseline.json")
	request := velero118.BaselineRequest{
		SchemaVersion:   velero118.BaselineRequestSchemaVersion,
		SourceNamespace: "source", SourcePVC: "volume", EvidencePrefix: "runtime/task22a",
	}
	writeJSON(t, requestPath, request, 0o600)
	response := `{"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":"volume","namespace":"source","uid":"source-uid","resourceVersion":"10","labels":{},"ownerReferences":[]},"spec":{"volumeName":"source-pv"},"status":{"phase":"Bound"}}`
	script := filepath.Join(directory, "kubectl")
	// #nosec G306 -- test-only executable in a per-test private directory.
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' \"$CLOUDRING_RESPONSE\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLOUDRING_RESPONSE", response)
	var output bytes.Buffer
	arguments := []string{"baseline", "--request", requestPath, "--output", outputPath, "--kubectl", script}
	if err := run(t.Context(), arguments, &output); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if strings.TrimSpace(output.String()) != "status=baseline_written" {
		t.Fatalf("stdout = %q", output.String())
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("baseline mode = %o", info.Mode().Perm())
	}
	// #nosec G304 -- outputPath is a test-owned path inside t.TempDir().
	before, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(t.Context(), arguments, &bytes.Buffer{}); err == nil {
		t.Fatal("existing private artifact was overwritten")
	}
	// #nosec G304 -- outputPath is a test-owned path inside t.TempDir().
	after, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("existing private artifact changed")
	}
}

func TestReadStrictJSONRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":"cloudring.restore-proof.collection-request/v1","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var request velero118.CollectionRequest
	if err := readStrictJSON(path, &request); err == nil {
		t.Fatal("unknown request field unexpectedly passed")
	}
}

func TestCleanupReadyBarrierIsPrivateAtomicAndNonOverwriting(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cleanup-ready.json")
	notice := velero118.CleanupReady{
		SchemaVersion:         velero118.CleanupReadySchemaVersion,
		Status:                velero118.CleanupReadyStatus,
		ReadyAt:               "2026-07-14T12:02:03Z",
		CleanupRunNonceSHA256: strings.Repeat("b", 64),
	}
	barrier := fileCleanupBarrier{path: path}
	if err := barrier.ReadyForCleanup(t.Context(), notice); err != nil {
		t.Fatalf("ReadyForCleanup() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cleanup marker mode = %o", info.Mode().Perm())
	}
	// #nosec G304 -- path is a test-owned artifact inside t.TempDir().
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded velero118.CleanupReady
	if err := json.Unmarshal(before, &decoded); err != nil || decoded != notice {
		t.Fatalf("cleanup marker = %#v, %v", decoded, err)
	}
	if err := barrier.ReadyForCleanup(t.Context(), notice); err == nil {
		t.Fatal("existing cleanup marker was overwritten")
	}
	// #nosec G304 -- path is a test-owned artifact inside t.TempDir().
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("existing cleanup marker changed")
	}
	invalid := []velero118.CleanupReady{notice, notice}
	invalid[0].ReadyAt = "2026-02-31T12:02:03Z"
	invalid[1].CleanupRunNonceSHA256 = strings.Repeat("z", 64)
	for index, candidate := range invalid {
		invalidPath := filepath.Join(t.TempDir(), "cleanup-ready.json")
		if err := (fileCleanupBarrier{path: invalidPath}).ReadyForCleanup(t.Context(), candidate); err == nil {
			t.Fatalf("invalid cleanup marker %d was published", index)
		}
		if _, err := os.Stat(invalidPath); !os.IsNotExist(err) {
			t.Fatalf("invalid cleanup marker %d left an artifact: %v", index, err)
		}
	}
}

func TestObservationReadyBarrierIsPrivateAtomicAndRequestBound(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "observation-ready.json")
	notice := velero118.DataUploadResultObservationReady{
		SchemaVersion:  velero118.DataUploadResultObservationReadySchemaVersion,
		Status:         velero118.DataUploadResultObservationReadyStatus,
		WatchStartedAt: "2026-07-14T12:00:00Z",
		RequestSHA256:  strings.Repeat("a", 64),
	}
	barrier := fileObservationReadyBarrier{path: path}
	if err := barrier.ReadyForRestore(t.Context(), notice); err != nil {
		t.Fatalf("ReadyForRestore() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("observation marker info = %#v, %v", info, err)
	}
	// #nosec G304 -- path is a test-owned artifact inside t.TempDir().
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded velero118.DataUploadResultObservationReady
	if err := json.Unmarshal(payload, &decoded); err != nil || decoded != notice {
		t.Fatalf("observation marker = %#v, %v", decoded, err)
	}
	if err := barrier.ReadyForRestore(t.Context(), notice); err == nil {
		t.Fatal("existing observation marker was overwritten")
	}
	invalid := notice
	invalid.RequestSHA256 = strings.Repeat("z", 64)
	if err := (fileObservationReadyBarrier{path: filepath.Join(t.TempDir(), "invalid.json")}).ReadyForRestore(t.Context(), invalid); err == nil {
		t.Fatal("invalid observation marker was published")
	}
}

func TestSamePathResolvesSymlinkedParents(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	aliasDirectory := filepath.Join(root, "alias")
	if err := os.Symlink(realDirectory, aliasDirectory); err != nil {
		t.Fatal(err)
	}
	if !samePath(filepath.Join(realDirectory, "artifact.json"), filepath.Join(aliasDirectory, "artifact.json")) {
		t.Fatal("symlinked destination aliases were not detected")
	}
}

func TestCollectRejectsExistingOutputBeforeReadingInputs(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	outputPath := filepath.Join(directory, "receipt.json")
	if err := os.WriteFile(outputPath, []byte("reserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{
		"collect", "--request", filepath.Join(directory, "missing-request.json"),
		"--baseline", filepath.Join(directory, "missing-baseline.json"), "--archive", filepath.Join(directory, "missing-archive.tar.gz"),
		"--data-upload-result-observation", filepath.Join(directory, "missing-result-observation.json"),
		"--data-probe-adapter", filepath.Join(directory, "missing-probe"), "--provider-adapter", filepath.Join(directory, "missing-provider"),
		"--cleanup-ready", filepath.Join(directory, "cleanup-ready.json"), "--output", outputPath,
	}
	err := run(t.Context(), arguments, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "artifact destination") {
		t.Fatalf("existing output preflight error = %v", err)
	}
}

func TestObserveRejectsExistingOutputBeforeReadingInputs(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	outputPath := filepath.Join(directory, "observation.json")
	if err := os.WriteFile(outputPath, []byte("reserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run(t.Context(), []string{
		"observe-data-upload-result", "--request", filepath.Join(directory, "missing-request.json"),
		"--ready", filepath.Join(directory, "ready.json"), "--output", outputPath,
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "destination") {
		t.Fatalf("existing observation preflight error = %v", err)
	}
}

func writeJSON(t *testing.T, path string, value any, mode os.FileMode) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, mode); err != nil {
		t.Fatal(err)
	}
}
