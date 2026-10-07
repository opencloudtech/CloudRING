// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

//go:build linux

package etcdrecovery

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

type pinnedTool struct {
	executable *protectedFile
	identity   string
	timeout    time.Duration
}

func openPinnedTool(ctx context.Context, path, expectedSHA256 string, timeout time.Duration) (toolRunner, error) {
	if !validSHA256(expectedSHA256) || timeout <= 0 || timeout > MaximumRunTimeout {
		return nil, errors.New("tool identity input is invalid")
	}
	executable, err := openProtectedFile(path, maximumToolBytes, trustedExecutable)
	if err != nil {
		return nil, errors.New("open recovery tool")
	}
	identity, _, err := executable.DigestContext(ctx)
	if err != nil || identity != expectedSHA256 {
		_ = executable.Close()
		return nil, errors.New("recovery tool digest does not match")
	}
	return &pinnedTool{executable: executable, identity: identity, timeout: timeout}, nil
}

func (tool *pinnedTool) IdentitySHA256() string {
	if tool == nil || tool.executable == nil {
		return ""
	}
	return tool.identity
}

func (tool *pinnedTool) VerifyVersion(ctx context.Context, workspace string) error {
	stdout, err := tool.run(ctx, nil, workspace, []string{"version"}, false)
	if err != nil {
		return err
	}
	defer clear(stdout)
	lines := strings.Split(strings.TrimSpace(string(stdout)), "\n")
	if len(lines) != 2 || strings.TrimSpace(lines[0]) != "etcdutl version: "+ToolVersion || !strings.HasPrefix(strings.TrimSpace(lines[1]), "API version: 3.6") {
		return errors.New("recovery tool version output is invalid")
	}
	return nil
}

func (tool *pinnedTool) Status(ctx context.Context, subject *protectedFile, workspace string) (snapshotStatus, error) {
	stdout, err := tool.run(ctx, subject, workspace, []string{"--write-out=json", "snapshot", "status", "/proc/self/fd/4"}, false)
	if err != nil {
		return snapshotStatus{}, err
	}
	defer clear(stdout)
	var status snapshotStatus
	if strictjson.DecodeExact(bytes.TrimSpace(stdout), &status) != nil {
		return snapshotStatus{}, errors.New("decode recovery status")
	}
	return status, nil
}

func (tool *pinnedTool) HashKV(ctx context.Context, subject *protectedFile, workspace string) (snapshotKVHash, error) {
	cleanWorkspace := filepath.Clean(workspace)
	disposableSource := subject != nil && subject.policy == exactOwnerOnly &&
		subject.path == filepath.Join(cleanWorkspace, "source-hash.db")
	privateRestored := subject != nil && subject.policy == currentOrRootReadOnly &&
		subject.path == filepath.Join(cleanWorkspace, "restored.etcd", "member", "snap", "db")
	if !filepath.IsAbs(cleanWorkspace) || (!disposableSource && !privateRestored) {
		return snapshotKVHash{}, errors.New("recovery KV hash input is not isolated")
	}
	stdout, err := tool.run(ctx, subject, workspace, []string{"--write-out=json", "hashkv", "/proc/self/fd/4"}, true)
	if err != nil {
		return snapshotKVHash{}, err
	}
	defer clear(stdout)
	var value snapshotKVHash
	if strictjson.DecodeExact(bytes.TrimSpace(stdout), &value) != nil {
		return snapshotKVHash{}, errors.New("decode recovery KV hash")
	}
	return value, nil
}

func (tool *pinnedTool) Restore(ctx context.Context, subject *protectedFile, dataDir string) error {
	clean := filepath.Clean(dataDir)
	if !filepath.IsAbs(clean) || clean != dataDir {
		return errors.New("restore directory is invalid")
	}
	loopbackPeerURL := "http://" + "127.0." + "0.1:2380"
	_, err := tool.run(ctx, subject, filepath.Dir(clean), []string{
		"snapshot", "restore", "/proc/self/fd/4",
		"--data-dir", clean,
		"--name", "isolated",
		"--initial-cluster", "isolated=" + loopbackPeerURL,
		"--initial-cluster-token", "cloudring-isolated-recovery",
		"--initial-advertise-peer-urls", loopbackPeerURL,
	}, false)
	return err
}

func (tool *pinnedTool) run(ctx context.Context, subject *protectedFile, workspace string, arguments []string, allowSubjectMutation bool) ([]byte, error) {
	if tool == nil || tool.executable == nil || tool.executable.file == nil || ctx == nil || tool.timeout <= 0 {
		return nil, errors.New("recovery tool is unavailable")
	}
	if tool.executable.ValidateStable() != nil || subject != nil && (subject.file == nil || subject.ValidateStable() != nil) {
		return nil, errors.New("recovery command input changed")
	}
	commandContext, cancel := context.WithTimeout(ctx, tool.timeout)
	defer cancel()
	// #nosec G204 -- /proc/self/fd/3 is the already opened, digest-pinned
	// executable; arguments are fixed worker literals and private workspace
	// paths, and the archive is passed as the already opened descriptor 4.
	command := exec.CommandContext(commandContext, "/proc/self/fd/3", arguments...)
	command.ExtraFiles = []*os.File{tool.executable.file}
	if subject != nil {
		command.ExtraFiles = append(command.ExtraFiles, subject.file)
	}
	command.Dir = workspace
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "TMPDIR=" + workspace}
	command.WaitDelay = time.Second
	stdout := &boundedOutput{maximum: maximumToolOutput}
	stderr := &boundedOutput{maximum: maximumToolOutput}
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Cancel = func() error {
		return terminateProcessGroup(command.Process)
	}
	err := command.Run()
	cleanupErr := terminateProcessGroup(command.Process)
	subjectValid := subject == nil || !allowSubjectMutation && subject.ValidateStable() == nil ||
		allowSubjectMutation && subject.ValidateIdentity() == nil
	inputStable := tool.executable.ValidateStable() == nil && subjectValid
	stderr.clear()
	if err != nil || cleanupErr != nil || !inputStable || stdout.exceeded || stderr.exceeded || commandContext.Err() != nil {
		stdout.clear()
		return nil, errors.New("offline recovery tool command failed")
	}
	output := append([]byte(nil), stdout.buffer.Bytes()...)
	stdout.clear()
	return output, nil
}

func terminateProcessGroup(process *os.Process) error {
	if process == nil {
		return os.ErrProcessDone
	}
	err := syscall.Kill(-process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func (tool *pinnedTool) Close() error {
	if tool == nil || tool.executable == nil {
		return nil
	}
	err := tool.executable.Close()
	tool.executable = nil
	return err
}

type boundedOutput struct {
	buffer   bytes.Buffer
	maximum  int64
	exceeded bool
}

func (output *boundedOutput) Write(data []byte) (int, error) {
	if output.exceeded {
		return len(data), nil
	}
	remaining := output.maximum - int64(output.buffer.Len())
	if int64(len(data)) > remaining {
		if remaining > 0 {
			_, _ = output.buffer.Write(data[:remaining])
		}
		output.exceeded = true
		return len(data), nil
	}
	return output.buffer.Write(data)
}

func (output *boundedOutput) clear() {
	clear(output.buffer.Bytes())
	output.buffer.Reset()
}
