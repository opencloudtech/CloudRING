// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/resilience/oneserverloss"
)

func TestReadyZRequiresEtcdAndTerminalSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("content-pinned executable runtime is Unix-only")
	}
	tests := []struct {
		name    string
		output  string
		wantErr bool
	}{
		{name: "complete", output: "[+]ping ok\n[+]etcd ok\nreadyz check passed\n"},
		{name: "missing etcd", output: "[+]ping ok\nreadyz check passed\n", wantErr: true},
		{name: "negative check", output: "[+]etcd ok\n[-]poststarthook failed\nreadyz check passed\n", wantErr: true},
		{name: "missing terminal result", output: "[+]etcd ok\n", wantErr: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			reader := readerForOutput(t, test.output)
			defer reader.Close()
			err := reader.ReadyZ(context.Background())
			if (err != nil) != test.wantErr {
				t.Fatalf("ReadyZ() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestReadyBarrierPublishesPrivateMarkerWithoutOverwrite(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "ready.json")
	marker := oneserverloss.ReadyMarker{
		SchemaVersion: oneserverloss.ReadyMarkerSchemaVersion, Status: oneserverloss.ReadyMarkerStatus,
		RequestSHA256: digest("request"), RunNonceSHA256: digest("nonce"), TargetNodeUIDSHA256: digest("node"),
		KubectlExecutableSHA256: digest("kubectl"), ProbeAdapterSHA256: digest("probe"),
		BaselineControlPlaneNodes: 3, BaselineEtcdMembers: 3, BaselineAPIServerMembers: 3,
		ReadyAt: time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	marker.MarkerSHA256 = markerSHA(marker)
	barrier := fileReadyBarrier{path: path}
	if err := barrier.ReadyForFault(context.Background(), marker); err != nil {
		t.Fatalf("ReadyForFault: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat marker: %v", err)
	}
	if !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("marker mode = %v, want private regular file", info.Mode())
	}
	if err := barrier.ReadyForFault(context.Background(), marker); err == nil {
		t.Fatal("ReadyForFault overwrote an existing marker")
	}
}

func TestRuntimeTreatsKubectlNotFoundAsExactAbsenceSignal(t *testing.T) {
	status := []byte(`{"apiVersion":"v1","kind":"Status","reason":"NotFound","code":404}`)
	if !kubernetesNotFound(status) || !kubernetesNotFound([]byte("Error from server (NotFound): requested object is absent")) {
		t.Fatal("kubernetesNotFound rejected a kubectl 404 form")
	}
	if kubernetesNotFound([]byte("generic command failure")) {
		t.Fatal("kubernetesNotFound accepted an unrelated failure")
	}
}

func TestProbeEnvironmentDropsAmbientCredentialAndProxyVariables(t *testing.T) {
	environment := restrictedEnvironment([]string{
		"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/protected/home", "HTTP_PROXY=http://proxy.invalid", "CLOUD_ACCESS_CONTEXT=synthetic-test-value",
	})
	if !slices.Contains(environment, "PATH=/usr/bin:/bin") || !slices.Contains(environment, "LANG=C") || !slices.Contains(environment, "LC_ALL=C") {
		t.Fatalf("restricted environment dropped required non-secret values: %v", environment)
	}
	for _, entry := range environment {
		if entry == "HOME=/protected/home" || entry == "HTTP_PROXY=http://proxy.invalid" || entry == "CLOUD_ACCESS_CONTEXT=synthetic-test-value" {
			t.Fatalf("restricted environment retained ambient credential surface: %q", entry)
		}
	}
}

func readerForOutput(t *testing.T, output string) *kubectlReader {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "kubectl")
	script := "#!/bin/sh\nprintf '%s' '" + output + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- private executable test fixture.
		t.Fatalf("write kubectl fixture: %v", err)
	}
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("create kubeconfig pipe: %v", err)
	}
	if _, err := writePipe.Write([]byte("apiVersion: v1\nkind: Config\n")); err != nil {
		t.Fatalf("write kubeconfig fixture: %v", err)
	}
	if err := writePipe.Close(); err != nil {
		t.Fatalf("close kubeconfig writer: %v", err)
	}
	reader, err := newKubectlReader(path, int(readPipe.Fd()))
	_ = readPipe.Close()
	if err != nil {
		t.Fatalf("newKubectlReader: %v", err)
	}
	return reader
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func markerSHA(marker oneserverloss.ReadyMarker) string {
	marker.MarkerSHA256 = ""
	// Keep this helper independent of the package's unexported digest helper.
	// JSON field order is deterministic for a struct. Marshal through the same
	// standard library used by the production implementation.
	payload, err := json.Marshal(marker)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
