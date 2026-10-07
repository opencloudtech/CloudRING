//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package kubeconfigpipe

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestReplayAttachesFreshPipeAndScrubsCredentialEnvironment(t *testing.T) {
	replay := newReplay(t, []byte("apiVersion: v1"))
	t.Cleanup(func() { _ = replay.Close() })
	for range 2 {
		command := exec.Command("/bin/sh", "-c", `
set -eu
test -z "${BW_SESSION+x}"
test -z "${BW_PASSWORD+x}"
test "$(cat "$KUBECONFIG")" = "apiVersion: v1"
printf ok
`)
		command.Env = append(os.Environ(), "BW_SESSION=must-not-leak", "BW_PASSWORD=must-not-leak", "KUBECONFIG=/tmp/must-not-win")
		var stdout bytes.Buffer
		command.Stdout = &stdout
		complete, err := replay.Attach(command)
		if err != nil {
			t.Fatal(err)
		}
		runErr := command.Run()
		completeErr := complete()
		if runErr != nil || completeErr != nil {
			t.Fatalf("run=%v complete=%v", runErr, completeErr)
		}
		if stdout.String() != "ok" {
			t.Fatalf("stdout = %q", stdout.String())
		}
		if err := complete(); err != nil {
			t.Fatalf("second completion = %v", err)
		}
	}
}

func TestReplayAccountsForExistingExtraFiles(t *testing.T) {
	replay := newReplay(t, []byte("apiVersion: v1"))
	t.Cleanup(func() { _ = replay.Close() })
	placeholder, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer placeholder.Close()
	command := exec.Command("/bin/sh", "-c", `test "$KUBECONFIG" = /dev/fd/4 && test "$(cat "$KUBECONFIG")" = "apiVersion: v1"`)
	command.ExtraFiles = []*os.File{placeholder}
	complete, err := replay.Attach(command)
	if err != nil {
		t.Fatal(err)
	}
	runErr := command.Run()
	completeErr := complete()
	if runErr != nil || completeErr != nil {
		t.Fatalf("run=%v complete=%v", runErr, completeErr)
	}
}

func TestNewFromFDRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte("apiVersion: v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- path is a test-owned regular file inside t.TempDir().
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := NewFromFD(int(file.Fd())); err == nil {
		t.Fatal("regular-file kubeconfig descriptor must fail closed")
	}
}

func TestNewFromFDRejectsInvalidDescriptor(t *testing.T) {
	if _, err := NewFromFD(2); err == nil {
		t.Fatal("stdio descriptor must fail closed")
	}
}

func TestNewFromFDRejectsInvalidPayload(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "nul", data: []byte{'a', 0, 'b'}},
		{name: "oversized", data: bytes.Repeat([]byte{'a'}, maxKubeconfigBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			writeDone := make(chan error, 1)
			go func() {
				_, writeErr := writer.Write(test.data)
				closeErr := writer.Close()
				if writeErr != nil {
					writeDone <- writeErr
					return
				}
				writeDone <- closeErr
			}()
			if replay, err := NewFromFD(int(reader.Fd())); err == nil {
				_ = replay.Close()
				t.Fatal("invalid kubeconfig payload must fail closed")
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-writeDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClosedReplayFailsClosed(t *testing.T) {
	replay := newReplay(t, []byte("apiVersion: v1"))
	if err := replay.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := replay.Attach(exec.Command("/bin/true")); err == nil {
		t.Fatal("closed replay must reject commands")
	}
}

func newReplay(t *testing.T, data []byte) *Replay {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := writer.Write(data)
		closeErr := writer.Close()
		if writeErr != nil {
			writeDone <- writeErr
			return
		}
		writeDone <- closeErr
	}()
	replay, err := NewFromFD(int(reader.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	return replay
}
