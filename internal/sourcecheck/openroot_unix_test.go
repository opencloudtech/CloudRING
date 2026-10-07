//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package sourcecheck

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestScan_OpenRoot_rejects_parent_symlink_escape_and_special_file(t *testing.T) {
	root := newRepository(t)
	outside := t.TempDir()
	sensitiveValue := "g" + "hp_" + strings.Repeat("o", 24)
	writeRepositoryFile(t, outside, "outside.txt", sensitiveValue)
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatalf("create parent symlink: %v", err)
	}
	_, err := Scan(Options{Root: root, Scope: ScopeFiles, Files: []string{"escape/outside.txt"}})
	if err == nil {
		t.Fatal("parent symlink escape was accepted")
	}
	if strings.Contains(err.Error(), outside) || strings.Contains(err.Error(), sensitiveValue) {
		t.Fatalf("sanitized error exposed outside path or content: %v", err)
	}

	fifo := filepath.Join(root, "pipe")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}
	if _, err := Scan(Options{Root: root, Scope: ScopeFiles, Files: []string{"pipe"}}); err == nil {
		t.Fatal("special FIFO input was accepted")
	}
}

func TestScan_OpenRoot_practical_parent_swap_never_reads_outside(t *testing.T) {
	root := newRepository(t)
	inside := filepath.Join(root, "inside")
	holding := filepath.Join(root, "holding")
	outside := t.TempDir()
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatalf("create inside fixture: %v", err)
	}
	writeRepositoryFile(t, root, "inside/target.txt", "safe inside content\n")
	writeRepositoryFile(t, outside, "target.txt", "g"+"hp_"+strings.Repeat("r", 24)+"\n")

	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		for index := 0; index < 250; index++ {
			if os.Rename(inside, holding) != nil {
				continue
			}
			if os.Symlink(outside, inside) == nil {
				_ = os.Remove(inside)
			}
			_ = os.Rename(holding, inside)
		}
	}()
	for index := 0; index < 250; index++ {
		report, err := Scan(Options{Root: root, Scope: ScopeFiles, Files: []string{"inside/target.txt"}})
		if err == nil && containsRule(report.Findings, "github_classic_token") {
			t.Fatal("descriptor-relative scan escaped during parent-directory swap")
		}
	}
	wait.Wait()
}

func TestReadRegularDescriptor_rejects_same_inode_mutation_after_read(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "mutable.txt")
	if err := os.WriteFile(path, []byte("initial safe content"), 0o600); err != nil {
		t.Fatalf("write mutable fixture: %v", err)
	}
	// #nosec G304 -- the test path is constructed beneath a fresh t.TempDir.
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open mutable fixture: %v", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat mutable fixture: %v", err)
	}
	_, err = readRegularDescriptor("mutable.txt", "worktree", file, info, func() {
		if writeErr := os.WriteFile(path, []byte("changed content with a different length"), 0o600); writeErr != nil {
			t.Fatalf("mutate fixture: %v", writeErr)
		}
	})
	if err == nil {
		t.Fatal("post-read descriptor metadata check accepted concurrent mutation")
	}
}

func TestScan_report_redacts_control_and_invalid_UTF8_paths(t *testing.T) {
	root := newRepository(t)
	rawPaths := []string{
		"line\nbreak.txt",
		"tab\tbreak.txt",
	}
	for _, rawPath := range rawPaths {
		writeRepositoryFile(t, root, rawPath, "safe content\n")
	}
	report, err := Scan(Options{Root: root, Scope: ScopeFull})
	if err != nil {
		t.Fatalf("full scan with raw-byte paths: %v", err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encode report: %v", err)
	}
	for _, rawPath := range rawPaths {
		if bytes.Contains(encoded, []byte(rawPath)) {
			t.Fatalf("report exposed unsafe raw path bytes: %q", rawPath)
		}
	}
	for _, identity := range report.ScannedFiles {
		if identity.SHA256 == "" || identity.Base64URL == "" || !strings.HasPrefix(identity.Display, "<redacted-path:") {
			t.Fatalf("unsafe path lacks redacted digest identity: %+v", identity)
		}
	}
	invalidPath := string([]byte{'i', 'n', 'v', 0xff, 'a', 'l', 'i', 'd'})
	identity := identifyPath(invalidPath)
	finding := bindFinding(Finding{Rule: "synthetic", Class: "test", Message: "synthetic"}, classifyInput(scanInput{
		path: invalidPath, variant: "synthetic", kind: "text", data: []byte("safe"),
	}))
	invalidEncoded, err := json.Marshal(struct {
		Identity PathIdentity `json:"identity"`
		Finding  Finding      `json:"finding"`
	}{identity, finding})
	if err != nil {
		t.Fatalf("encode invalid UTF-8 identity: %v", err)
	}
	if bytes.Contains(invalidEncoded, []byte(invalidPath)) || !strings.HasPrefix(identity.Display, "<redacted-path:") || identity.SHA256 == "" || identity.Base64URL == "" {
		t.Fatalf("invalid UTF-8 path was not losslessly identified and redacted: %s", invalidEncoded)
	}
	roundTrip := nulStrings(append([]byte(invalidPath), 0))
	if len(roundTrip) != 1 || !bytes.Equal([]byte(roundTrip[0]), []byte(invalidPath)) {
		t.Fatal("NUL-delimited Git path parsing changed invalid UTF-8 bytes")
	}
}
