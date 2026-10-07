// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProtectedOperatorInputRejectsSymlinkFIFOAndPermissiveFile(t *testing.T) {
	directory := t.TempDir()
	protected := filepath.Join(directory, "protected.jwt")
	if err := os.WriteFile(protected, []byte("synthetic"), 0o600); err != nil {
		t.Fatalf("write protected fixture: %v", err)
	}
	if _, err := readOperatorFile(protected, 1024, true); err != nil {
		t.Fatalf("read protected regular fixture: %v", err)
	}

	permissive := filepath.Join(directory, "permissive.jwt")
	// #nosec G306 -- deliberately permissive mode proves the reader rejects it.
	if err := os.WriteFile(permissive, []byte("synthetic"), 0o644); err != nil {
		t.Fatalf("write permissive fixture: %v", err)
	}
	if _, err := readOperatorFile(permissive, 1024, true); err == nil {
		t.Fatal("owner-only read accepted a group/world-readable file")
	}

	alias := filepath.Join(directory, "alias.jwt")
	if err := os.Symlink(protected, alias); err != nil {
		t.Fatalf("create symlink fixture: %v", err)
	}
	if _, err := readOperatorFile(alias, 1024, true); err == nil {
		t.Fatal("protected read followed a symlink")
	}

	fifo := filepath.Join(directory, "input.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("create fifo fixture: %v", err)
	}
	if _, err := readOperatorFile(fifo, 1024, true); err == nil {
		t.Fatal("protected read accepted a FIFO")
	}
}
