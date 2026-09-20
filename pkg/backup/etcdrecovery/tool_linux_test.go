// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

//go:build linux

package etcdrecovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPinnedToolCancellationKillsProcessGroup(t *testing.T) {
	root := resolvedTempDir(t)
	source := filepath.Join(root, "helper.go")
	executable := filepath.Join(root, "etcdutl-helper")
	helper := `package main
import (
  "os"
  "os/exec"
  "path/filepath"
  "strconv"
)
func main() {
  child := exec.Command("/bin/sleep", "30")
  if err := child.Start(); err != nil { os.Exit(2) }
  if err := os.WriteFile(filepath.Join(os.Getenv("TMPDIR"), "child.pid"), []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil { os.Exit(3) }
  _ = child.Wait()
}`
	if err := os.WriteFile(source, []byte(helper), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- fixed Go compiler and repository-owned synthetic test paths.
	build := exec.Command("go", "build", "-trimpath", "-o", executable, source)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build synthetic tool: %v: %s", err, output)
	}
	opened, err := openProtectedFile(executable, maximumToolBytes, trustedExecutable)
	if err != nil {
		t.Fatal(err)
	}
	digest, _, err := opened.Digest()
	_ = opened.Close()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := openPinnedTool(context.Background(), executable, digest, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := runner.VerifyVersion(ctx, workspace); err == nil {
		t.Fatal("cancelled synthetic tool unexpectedly succeeded")
	}
	pidPath := filepath.Join(workspace, "child.pid")
	var pid int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		payload, readErr := os.ReadFile(pidPath) // #nosec G304 -- fixed synthetic test workspace path.
		if readErr == nil {
			pid, err = strconv.Atoi(strings.TrimSpace(string(payload)))
			if err != nil {
				t.Fatal(err)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid <= 0 {
		t.Fatal("synthetic child PID was not recorded")
	}
	for time.Now().Before(deadline) {
		state, stateErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)) // #nosec G304 -- PID was parsed from the synthetic helper output.
		if errors.Is(stateErr, os.ErrNotExist) || stateErr == nil && processState(state) == "Z" {
			return
		}
		if killErr := syscall.Kill(pid, 0); errors.Is(killErr, syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("synthetic child process %d survived process-group cancellation", pid)
}

func TestPinnedToolSuccessKillsDetachedDescendants(t *testing.T) {
	root := resolvedTempDir(t)
	source := filepath.Join(root, "helper.go")
	executable := filepath.Join(root, "etcdutl-helper")
	helper := `package main
import (
  "fmt"
  "os"
  "os/exec"
  "path/filepath"
  "strconv"
)
func main() {
  child := exec.Command("/bin/sleep", "30")
  if err := child.Start(); err != nil { os.Exit(2) }
  if err := os.WriteFile(filepath.Join(os.Getenv("TMPDIR"), "child.pid"), []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil { os.Exit(3) }
  fmt.Println("etcdutl version: 3.6.14")
  fmt.Println("API version: 3.6")
}`
	if err := os.WriteFile(source, []byte(helper), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- fixed Go compiler and repository-owned synthetic test paths.
	build := exec.Command("go", "build", "-trimpath", "-o", executable, source)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build synthetic tool: %v: %s", err, output)
	}
	opened, err := openProtectedFile(executable, maximumToolBytes, trustedExecutable)
	if err != nil {
		t.Fatal(err)
	}
	digest, _, err := opened.Digest()
	_ = opened.Close()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := openPinnedTool(context.Background(), executable, digest, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := runner.VerifyVersion(context.Background(), workspace); err != nil {
		t.Fatal(err)
	}
	pidPayload, err := os.ReadFile(filepath.Join(workspace, "child.pid")) // #nosec G304 -- fixed synthetic workspace.
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidPayload)))
	if err != nil || pid <= 0 {
		t.Fatalf("child PID = %q, %v", pidPayload, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state, stateErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)) // #nosec G304 -- synthetic PID.
		if errors.Is(stateErr, os.ErrNotExist) || stateErr == nil && processState(state) == "Z" {
			return
		}
		if killErr := syscall.Kill(pid, 0); errors.Is(killErr, syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("synthetic child process %d survived successful parent exit", pid)
}

func TestHashKVRejectsAnyPathOutsideFixedPrivateTargets(t *testing.T) {
	root := resolvedTempDir(t)
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(workspace, "archive.db")
	if err := os.WriteFile(wrongPath, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	subject, err := openProtectedFile(wrongPath, MaxArchiveBytes, exactOwnerOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Close()
	_, err = (&pinnedTool{}).HashKV(context.Background(), subject, workspace)
	if err == nil || !strings.Contains(err.Error(), "not isolated") {
		t.Fatalf("HashKV wrong-path error = %v", err)
	}
}

func processState(stat []byte) string {
	closing := strings.LastIndexByte(string(stat), ')')
	if closing < 0 {
		return ""
	}
	fields := strings.Fields(string(stat[closing+1:]))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
