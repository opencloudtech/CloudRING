// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifyShippedRoadmap(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", "--root", shippedRoadmapRoot(t)}, &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("run() code = %d, stderr = %q", code, stderr.String())
	}
	if got, want := stdout.String(), "cloudring_roadmap_verified goals=28 requirements=29\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestVerifyFailsClosedWithoutDisclosingRoot(t *testing.T) {
	privatePart := "operator-private-roadmap-location"
	root := filepath.Join(t.TempDir(), privatePart)
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", "--root", root}, &stdout, &stderr)
	if code != exitFailure {
		t.Fatalf("run() code = %d, want %d", code, exitFailure)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if got := stderr.String(); got != validationFailedMarker || strings.Contains(got, privatePart) || strings.Contains(got, root) {
		t.Fatalf("stderr was not a sanitized stable marker: %q", got)
	}
}

func TestVerifyRejectsMalformedRoadmapWithoutDisclosingDetails(t *testing.T) {
	root := t.TempDir()
	repository, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.WriteFile("roadmap.yaml", []byte("unknownPrivateField: should-not-be-printed\n"), 0o644); err != nil {
		if closeErr := repository.Close(); closeErr != nil {
			t.Fatalf("write malformed roadmap: %v; close root: %v", err, closeErr)
		}
		t.Fatal(err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", "--root", root}, &stdout, &stderr)
	if code != exitFailure || stdout.Len() != 0 || stderr.String() != validationFailedMarker {
		t.Fatalf("run() = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), "unknownPrivateField") {
		t.Fatal("stderr disclosed roadmap details")
	}
}

func TestVerifyRejectsInvalidArgumentsWithoutEcho(t *testing.T) {
	privateArgument := "operator-private-argument"
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", privateArgument}, &stdout, &stderr)
	if code != exitUsage || stdout.Len() != 0 || stderr.String() != invalidArgumentsMarker {
		t.Fatalf("run() = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), privateArgument) {
		t.Fatal("stderr disclosed an invalid argument")
	}
}

func TestVerifyReportsOutputFailureWithoutValidationDetails(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"verify", "--root", shippedRoadmapRoot(t)}, failingWriter{}, &stderr)
	if code != exitFailure || stderr.String() != outputFailedMarker {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
}

func TestVerifyTreatsShortWriteAsOutputFailure(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"verify", "--root", shippedRoadmapRoot(t)}, shortWriter{}, &stderr)
	if code != exitFailure || stderr.String() != outputFailedMarker {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
}

func shippedRoadmapRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "roadmap")
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic output failure")
}

type shortWriter struct{}

func (shortWriter) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	return len(payload) - 1, nil
}
