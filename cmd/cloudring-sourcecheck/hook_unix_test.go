//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrackedHook_drops_remoteURL_before_child_process_argv(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	hook := filepath.Join(root, ".githooks", "pre-push")
	temporary := t.TempDir()
	capture := filepath.Join(temporary, "argv")
	environmentCapture := filepath.Join(temporary, "environment")
	fakeGo := filepath.Join(temporary, "go")
	// #nosec G306 -- this private t.TempDir fixture must be owner-executable to replace go in PATH.
	if err := os.WriteFile(fakeGo, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SOURCECHECK_ARGV_CAPTURE\"\nenv > \"$SOURCECHECK_ENV_CAPTURE\"\ncat >/dev/null\n"), 0o700); err != nil {
		t.Fatalf("write fake go: %v", err)
	}
	remoteSecret := "https://user:" + "pass" + "word@example.test/private/repository"
	// #nosec G204 -- test executes the tracked hook with controlled synthetic arguments.
	command := exec.Command(hook, "origin", remoteSecret)
	command.Dir = root
	command.Env = append(os.Environ(), "PATH="+temporary+string(os.PathListSeparator)+os.Getenv("PATH"), "SOURCECHECK_ARGV_CAPTURE="+capture, "SOURCECHECK_ENV_CAPTURE="+environmentCapture)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run tracked hook: %v: %s", err, output)
	}
	if strings.Contains(string(output), remoteSecret) {
		t.Fatal("tracked hook exposed remote URL in child output")
	}
	// #nosec G304 -- the capture path is constructed beneath a fresh t.TempDir.
	childArgv, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("read captured child argv: %v", err)
	}
	if strings.Contains(string(childArgv), remoteSecret) {
		t.Fatalf("tracked hook forwarded remote URL into child argv: %q", childArgv)
	}
	if strings.Join(strings.Fields(string(childArgv)), " ") != "run ./cmd/cloudring-sourcecheck pre-push-hook origin" {
		t.Fatalf("unexpected sourcecheck child argv: %q", childArgv)
	}
	// #nosec G304 -- the environment capture path is beneath a fresh t.TempDir.
	childEnvironment, err := os.ReadFile(environmentCapture)
	if err != nil {
		t.Fatalf("read captured child environment: %v", err)
	}
	if strings.Contains(string(childEnvironment), remoteSecret) {
		t.Fatal("tracked hook forwarded remote URL into child environment")
	}
}
