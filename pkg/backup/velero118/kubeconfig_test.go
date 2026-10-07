//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package velero118

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
)

func TestKubectlReaderReplaysPipeBackedKubeconfigAndScrubsEnvironment(t *testing.T) {
	directory := t.TempDir()
	kubectl := filepath.Join(directory, "kubectl")
	script := `#!/bin/sh
set -eu
test -z "${BW_SESSION+x}"
test -z "${BW_PASSWORD+x}"
test -n "${KUBECONFIG:-}"
test "$(cat "$KUBECONFIG")" = "apiVersion: v1"
test "$1" = "get"
test "$2" = "--raw"
case "$3" in
  */persistentvolumeclaims/one) name=one ;;
  */persistentvolumeclaims/two) name=two ;;
  *) exit 64 ;;
esac
printf '{"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":"%s","namespace":"source","uid":"uid-%s","resourceVersion":"1"},"spec":{},"status":{}}' "$name" "$name"
`
	// #nosec G306 -- test-only executable in a per-test private directory.
	if err := os.WriteFile(kubectl, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BW_SESSION", "must-not-reach-kubectl")
	t.Setenv("BW_PASSWORD", "must-not-reach-kubectl")

	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := pipeWriter.Write([]byte("apiVersion: v1"))
		closeErr := pipeWriter.Close()
		if writeErr != nil {
			writeDone <- writeErr
			return
		}
		writeDone <- closeErr
	}()
	reader, err := NewKubectlReaderFromKubeconfigFD(kubectl, int(pipeReader.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeReader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	for _, name := range []string{"one", "two"} {
		data, err := reader.Get(context.Background(), restoreproof.CoreV1PVCGVR, "source", name)
		if err != nil {
			t.Fatalf("Get(%q): %v", name, err)
		}
		if !strings.Contains(string(data), `"name":"`+name+`"`) {
			t.Fatalf("Get(%q) returned wrong object", name)
		}
		zeroBytes(data)
	}
}
