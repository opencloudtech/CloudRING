// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package privateartifact

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteNewJSONPublishesOwnerOnlyWithoutOverwrite(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "evidence.json")
	if err := WriteNewJSON(path, map[string]bool{"synthetic": true}); err != nil {
		t.Fatalf("WriteNewJSON: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat evidence: %v", err)
	}
	if !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("evidence mode = %v, want regular 0600", info.Mode())
	}
	if err := WriteNewJSON(path, map[string]bool{"replacement": true}); err == nil {
		t.Fatal("WriteNewJSON replaced an existing artifact")
	}
}

func TestWriteNewRejectsSymlinkDestinationAndParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require Windows developer mode")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	alias := filepath.Join(directory, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatalf("symlink destination: %v", err)
	}
	if err := WriteNew(alias, []byte("replacement")); err == nil {
		t.Fatal("WriteNew followed a destination symlink")
	}

	realDirectory := filepath.Join(directory, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}
	parentAlias := filepath.Join(directory, "parent-alias")
	if err := os.Symlink(realDirectory, parentAlias); err != nil {
		t.Fatalf("symlink parent: %v", err)
	}
	if err := WriteNew(filepath.Join(parentAlias, "artifact"), []byte("data")); err == nil {
		t.Fatal("WriteNew followed a parent-directory symlink")
	}
}

func TestWriteNewRejectsWritableParentDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory mode is not available on Windows")
	}
	directory := t.TempDir()
	// #nosec G302 -- deliberately permissive mode proves the writer rejects it.
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatalf("chmod fixture directory: %v", err)
	}
	if err := WriteNew(filepath.Join(directory, "artifact"), []byte("data")); err == nil {
		t.Fatal("WriteNew accepted a group/world-writable parent directory")
	}
}
