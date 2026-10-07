// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package privateartifact

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"golang.org/x/sys/unix"
)

func TestReadJSONRejectsPermissiveHardLinkedAndSymlinkInputs(t *testing.T) {
	directory := t.TempDir()
	permissive := filepath.Join(directory, "permissive.json")
	// #nosec G306 -- deliberately permissive mode proves the reader rejects it.
	if err := os.WriteFile(permissive, []byte(`{"known":"value"}`), 0o644); err != nil {
		t.Fatalf("write permissive fixture: %v", err)
	}
	var destination exactFixture
	if err := ReadJSON(permissive, &destination); err == nil {
		t.Fatal("ReadJSON accepted a group/world-readable artifact")
	}

	protected := filepath.Join(directory, "protected.json")
	if err := os.WriteFile(protected, []byte(`{"known":"value"}`), 0o600); err != nil {
		t.Fatalf("write protected fixture: %v", err)
	}
	hardLink := filepath.Join(directory, "hard-link.json")
	if err := os.Link(protected, hardLink); err != nil {
		t.Fatalf("create hard-link fixture: %v", err)
	}
	if err := ReadJSON(protected, &destination); err == nil {
		t.Fatal("ReadJSON accepted a multiply linked artifact")
	}

	alias := filepath.Join(directory, "alias.json")
	if err := os.Symlink(protected, alias); err != nil {
		t.Fatalf("create symlink fixture: %v", err)
	}
	if err := ReadJSON(alias, &destination); err == nil {
		t.Fatal("ReadJSON followed a symbolic link")
	}
}

func TestReadJSONRejectsUntrustedParentAndOversizedInput(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "input.json")
	if err := os.WriteFile(path, []byte(`{"known":"value"}`), 0o600); err != nil {
		t.Fatalf("write input fixture: %v", err)
	}
	// #nosec G302 -- deliberately permissive mode proves the reader rejects it.
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatalf("chmod fixture directory: %v", err)
	}
	// #nosec G302 -- cleanup restores the owner-only directory fixture.
	t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })
	var destination exactFixture
	if err := ReadJSON(path, &destination); err == nil {
		t.Fatal("ReadJSON accepted an untrusted parent directory")
	}
	// #nosec G302 -- restore the owner-only directory before the next assertion.
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("restore fixture directory mode: %v", err)
	}

	oversized := filepath.Join(directory, "oversized.json")
	// #nosec G304 -- the path is constructed beneath a fresh t.TempDir.
	file, err := os.OpenFile(oversized, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create oversized fixture: %v", err)
	}
	if err := file.Truncate(strictjson.MaxDocumentBytes + 1); err != nil {
		_ = file.Close()
		t.Fatalf("truncate oversized fixture: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close oversized fixture: %v", err)
	}
	if err := ReadJSON(oversized, &destination); err == nil {
		t.Fatal("ReadJSON accepted an oversized artifact")
	}
}

func TestReadOwnerOnlyRejectsSpecialFileAndPostReadPathReplacement(t *testing.T) {
	directory := t.TempDir()
	fifo := filepath.Join(directory, "input.pipe")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("create FIFO fixture: %v", err)
	}
	if _, err := readOwnerOnly(fifo, 1024, nil); err == nil {
		t.Fatal("readOwnerOnly accepted a FIFO")
	}

	path := filepath.Join(directory, "input.json")
	payload := []byte(`{"known":"value"}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write stable-path fixture: %v", err)
	}
	holding := filepath.Join(directory, "holding.json")
	_, err := readOwnerOnly(path, int64(len(payload)), func() {
		if renameErr := os.Rename(path, holding); renameErr != nil {
			t.Fatalf("rename selected artifact: %v", renameErr)
		}
		if writeErr := os.WriteFile(path, payload, 0o600); writeErr != nil {
			t.Fatalf("write replacement artifact: %v", writeErr)
		}
	})
	if err == nil {
		t.Fatal("readOwnerOnly accepted a post-read path replacement")
	}
}
