// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

// Package secureexec pins an executable identity once and runs bounded child
// commands inside the CloudRING process-tree and kubeconfig replay boundary.
package secureexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/kubeconfigpipe"
)

const (
	maxPinnedExecutableBytes = 512 << 20
	maxCapturedOutputBytes   = 64 << 20
)

type Executable struct {
	mu             sync.RWMutex
	file           *os.File
	invocationPath string
	snapshotDir    string
	useDescriptor  bool
	identitySHA256 string
	timeout        time.Duration
	closed         bool
}

// Pin resolves binary once, snapshots its exact regular executable content,
// and returns an identity-stable runner. PATH is never consulted again.
func Pin(binary string, timeout time.Duration) (*Executable, error) {
	if strings.TrimSpace(binary) == "" {
		return nil, errors.New("executable name is required")
	}
	path := binary
	if !filepath.IsAbs(path) {
		resolved, err := exec.LookPath(path)
		if err != nil {
			return nil, errors.New("resolve executable")
		}
		path = resolved
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New("resolve executable")
	}
	return PinAbsolute(absolute, timeout)
}

// PinAbsolute pins one caller-selected absolute executable identity.
func PinAbsolute(path string, timeout time.Duration) (*Executable, error) {
	if timeout <= 0 || runtime.GOOS != "linux" && runtime.GOOS != "darwin" || !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
		return nil, errors.New("pinned executable runtime or path is unsupported")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil || !filepath.IsAbs(resolved) {
		return nil, errors.New("resolve executable identity")
	}
	// #nosec G304 -- resolved is an absolute, symlink-resolved executable identity and is validated below as bounded and regular.
	source, err := os.Open(resolved)
	if err != nil {
		return nil, errors.New("open executable identity")
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Size() <= 0 || info.Size() > maxPinnedExecutableBytes {
		return nil, errors.New("executable identity is invalid")
	}
	snapshotDir, err := os.MkdirTemp("", ".cloudring-pinned-exec-")
	if err != nil {
		return nil, errors.New("create pinned executable directory")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(snapshotDir)
		}
	}()
	// #nosec G302 -- the directory must be searchable only by its owner so its private executable can run.
	if err := os.Chmod(snapshotDir, 0o700); err != nil {
		return nil, errors.New("protect pinned executable directory")
	}
	snapshotPath := filepath.Join(snapshotDir, "executable")
	// #nosec G304 G302 -- snapshotPath is inside the fresh private directory and an executable copy requires owner execute permission.
	snapshot, err := os.OpenFile(snapshotPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		return nil, errors.New("create pinned executable snapshot")
	}
	hasher := sha256.New()
	copied, copyErr := io.Copy(io.MultiWriter(snapshot, hasher), io.LimitReader(source, maxPinnedExecutableBytes+1))
	chmodErr := snapshot.Chmod(0o500)
	syncErr := snapshot.Sync()
	closeErr := snapshot.Close()
	if copyErr != nil || chmodErr != nil || syncErr != nil || closeErr != nil || copied != info.Size() {
		return nil, errors.New("write pinned executable snapshot")
	}
	// #nosec G304 -- snapshotPath is the exact private file created above and is revalidated immediately after opening.
	pinned, err := os.Open(snapshotPath)
	if err != nil {
		return nil, errors.New("open pinned executable snapshot")
	}
	pinnedInfo, statErr := pinned.Stat()
	if statErr != nil || !pinnedInfo.Mode().IsRegular() || pinnedInfo.Mode().Perm()&0o111 == 0 || pinnedInfo.Size() != info.Size() {
		_ = pinned.Close()
		return nil, errors.New("pinned executable snapshot is invalid")
	}
	invocationPath := snapshotPath
	useDescriptor := runtime.GOOS == "linux"
	retainedDir := snapshotDir
	if useDescriptor {
		invocationPath = "/proc/self/fd/3"
		if err := os.Remove(snapshotPath); err != nil {
			_ = pinned.Close()
			return nil, errors.New("unlink pinned executable snapshot")
		}
		if err := os.Remove(snapshotDir); err != nil {
			_ = pinned.Close()
			return nil, errors.New("remove pinned executable directory")
		}
		retainedDir = ""
	}
	cleanup = false
	return &Executable{
		file: pinned, invocationPath: invocationPath, snapshotDir: retainedDir,
		useDescriptor: useDescriptor, identitySHA256: hex.EncodeToString(hasher.Sum(nil)), timeout: timeout,
	}, nil
}

func (executable *Executable) IdentitySHA256() string {
	if executable == nil {
		return ""
	}
	executable.mu.RLock()
	defer executable.mu.RUnlock()
	if executable.closed {
		return ""
	}
	return executable.identitySHA256
}

// Run executes the pinned identity with bounded output. The optional replay is
// attached after the executable descriptor, so its fd is calculated safely.
func (executable *Executable) Run(ctx context.Context, arguments []string, input []byte, maximumStdout, maximumStderr int64, replay *kubeconfigpipe.Replay) ([]byte, []byte, error) {
	return executable.run(ctx, arguments, input, maximumStdout, maximumStderr, nil, replay, nil)
}

// RunWithEnvironment executes the pinned identity with an explicit environment.
// A non-nil environment prevents ambient credentials from being inherited by
// installation-provided adapters. Kubeconfig replay applies its own further
// allowlist and anonymous descriptor after this boundary.
func (executable *Executable) RunWithEnvironment(ctx context.Context, arguments []string, input []byte, maximumStdout, maximumStderr int64, environment []string, replay *kubeconfigpipe.Replay) ([]byte, []byte, error) {
	if environment == nil || !validEnvironment(environment) {
		return nil, nil, errors.New("invalid pinned command environment")
	}
	return executable.run(ctx, arguments, input, maximumStdout, maximumStderr, append([]string(nil), environment...), replay, nil)
}

// RunWithEnvironmentNames retains explicitly approved additional environment
// names through kubeconfig replay. Existing RunWithEnvironment filtering remains
// unchanged. Values must already be present in the explicit environment.
func (executable *Executable) RunWithEnvironmentNames(ctx context.Context, arguments []string, input []byte, maximumStdout, maximumStderr int64, environment []string, replay *kubeconfigpipe.Replay, environmentNames []string) ([]byte, []byte, error) {
	if environment == nil || !validEnvironment(environment) || kubeconfigpipe.ValidateEnvironmentNames(environmentNames) != nil {
		return nil, nil, errors.New("invalid pinned command environment")
	}
	return executable.run(ctx, arguments, input, maximumStdout, maximumStderr, append([]string(nil), environment...), replay, append([]string(nil), environmentNames...))
}

func (executable *Executable) run(ctx context.Context, arguments []string, input []byte, maximumStdout, maximumStderr int64, environment []string, replay *kubeconfigpipe.Replay, environmentNames []string) ([]byte, []byte, error) {
	if executable == nil || ctx == nil || maximumStdout <= 0 || maximumStdout > maxCapturedOutputBytes ||
		maximumStderr <= 0 || maximumStderr > maxCapturedOutputBytes {
		return nil, nil, errors.New("invalid pinned command")
	}
	executable.mu.RLock()
	defer executable.mu.RUnlock()
	if executable.closed || executable.file == nil || executable.timeout <= 0 {
		return nil, nil, errors.New("pinned executable is closed")
	}
	if !executable.useDescriptor {
		if err := executable.verifySnapshot(); err != nil {
			return nil, nil, errors.New("verify pinned executable")
		}
	}
	invocationContext, cancel := context.WithTimeout(ctx, executable.timeout)
	defer cancel()
	// #nosec G204 -- invocationPath is the retained content-pinned executable and arguments are passed directly without a shell.
	command := exec.CommandContext(invocationContext, executable.invocationPath, arguments...)
	if executable.useDescriptor {
		command.ExtraFiles = []*os.File{executable.file}
	}
	if environment != nil {
		command.Env = environment
	}
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	stdout := boundedBuffer{maximum: int(maximumStdout)}
	stderr := boundedBuffer{maximum: int(maximumStderr)}
	command.Stdout = &stdout
	command.Stderr = &stderr
	var runErr error
	if len(environmentNames) == 0 {
		runErr = kubeconfigpipe.Run(command, replay)
	} else {
		runErr = kubeconfigpipe.RunWithEnvironmentNames(command, replay, environmentNames)
	}
	if stdout.exceeded || stderr.exceeded {
		zero(stdout.buffer.Bytes())
		zero(stderr.buffer.Bytes())
		return nil, nil, errors.New("command output exceeded limit")
	}
	output := append([]byte(nil), stdout.buffer.Bytes()...)
	errorOutput := append([]byte(nil), stderr.buffer.Bytes()...)
	zero(stdout.buffer.Bytes())
	zero(stderr.buffer.Bytes())
	if runErr != nil {
		if kubeconfigpipe.IsLifecycleFailure(runErr) {
			zero(output)
			zero(errorOutput)
			return nil, nil, errors.New("pinned command lifecycle failed")
		}
		return output, errorOutput, errors.New("pinned command failed")
	}
	zero(errorOutput)
	return output, nil, nil
}

func validEnvironment(environment []string) bool {
	seen := make(map[string]struct{}, len(environment))
	for _, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == "" || strings.ContainsAny(name, "=\x00\r\n") || strings.ContainsRune(entry, '\x00') {
			return false
		}
		if _, duplicate := seen[name]; duplicate {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

func (executable *Executable) verifySnapshot() error {
	if executable.snapshotDir == "" || executable.invocationPath == "" {
		return errors.New("pinned executable snapshot is missing")
	}
	// #nosec G304 -- invocationPath is the private pinned snapshot created and retained by this object.
	file, err := os.Open(executable.invocationPath)
	if err != nil {
		return err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(file, maxPinnedExecutableBytes+1)); err != nil {
		return err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != executable.identitySHA256 {
		return errors.New("pinned executable identity changed")
	}
	return nil
}

func (executable *Executable) Close() error {
	if executable == nil {
		return nil
	}
	executable.mu.Lock()
	defer executable.mu.Unlock()
	if executable.closed {
		return nil
	}
	executable.closed = true
	closeErr := executable.file.Close()
	removeErr := error(nil)
	if executable.snapshotDir != "" {
		removeErr = os.RemoveAll(executable.snapshotDir)
	}
	return errors.Join(closeErr, removeErr)
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	maximum  int
	exceeded bool
}

func (writer *boundedBuffer) Write(value []byte) (int, error) {
	if writer.exceeded {
		return len(value), nil
	}
	remaining := writer.maximum - writer.buffer.Len()
	if remaining <= 0 || len(value) > remaining {
		if remaining > 0 {
			_, _ = writer.buffer.Write(value[:remaining])
		}
		writer.exceeded = true
		return len(value), nil
	}
	_, _ = writer.buffer.Write(value)
	return len(value), nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
