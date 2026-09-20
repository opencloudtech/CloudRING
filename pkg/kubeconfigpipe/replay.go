// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

// Package kubeconfigpipe replays one bounded pipe-backed kubeconfig through a
// fresh anonymous pipe for each child command without placing the credential
// in argv, the environment, or a regular file.
package kubeconfigpipe

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxKubeconfigBytes = 4 << 20
	replayWriteTimeout = 30 * time.Second
)

// Replay owns an in-memory kubeconfig until Close. It is concurrency-safe.
type Replay struct {
	mu     sync.Mutex
	data   []byte
	closed bool
}

// NewFromFD reads a kubeconfig from an inherited anonymous or named pipe.
// The caller retains ownership of the original descriptor; reading its
// duplicate consumes the same stream.
func NewFromFD(fd int) (*Replay, error) {
	if fd < 3 || fd > 1024 {
		return nil, errors.New("pipe-backed kubeconfig descriptor is invalid")
	}
	file, err := duplicateFD(fd)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	if statErr != nil || info.Mode()&os.ModeNamedPipe == 0 {
		_ = file.Close()
		return nil, errors.New("kubeconfig descriptor must be an anonymous or named pipe")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxKubeconfigBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > maxKubeconfigBytes || bytes.IndexByte(data, 0) >= 0 {
		zero(data)
		return nil, errors.New("read pipe-backed kubeconfig")
	}
	return &Replay{data: data}, nil
}

// Attach adds a fresh replay pipe to an unstarted command and returns an
// idempotent completion function. Low-level callers must contain and clean the
// complete process tree before invoking completion; prefer Run for the safe
// combined lifecycle.
func (replay *Replay) Attach(command *exec.Cmd) (func() error, error) {
	return replay.attach(command, nil)
}

func (replay *Replay) attach(command *exec.Cmd, environmentNames []string) (func() error, error) {
	if replay == nil || command == nil || command.Process != nil {
		return nil, errors.New("invalid kubeconfig replay command")
	}
	replay.mu.Lock()
	if replay.closed || len(replay.data) == 0 {
		replay.mu.Unlock()
		return nil, errors.New("pipe-backed kubeconfig is closed")
	}
	data := append([]byte(nil), replay.data...)
	replay.mu.Unlock()

	reader, writer, err := os.Pipe()
	if err != nil {
		zero(data)
		return nil, errors.New("create kubeconfig replay pipe")
	}
	if err := writer.SetWriteDeadline(time.Now().Add(replayWriteTimeout)); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		zero(data)
		return nil, errors.New("bound kubeconfig replay pipe")
	}
	fd := 3 + len(command.ExtraFiles)
	command.ExtraFiles = append(command.ExtraFiles, reader)
	environment := command.Env
	if environment == nil {
		environment = os.Environ()
	}
	command.Env = restrictedEnvironmentWithNames(environment, fd, environmentNames)

	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := io.Copy(writer, bytes.NewReader(data))
		closeErr := writer.Close()
		zero(data)
		if writeErr != nil {
			writeDone <- writeErr
			return
		}
		writeDone <- closeErr
	}()

	var once sync.Once
	var completionErr error
	complete := func() error {
		once.Do(func() {
			_ = reader.Close()
			// Closing the writer cancels a blocked write even when an escaped or
			// not-yet-reaped descendant retained the read descriptor.
			_ = writer.Close()
			if err := <-writeDone; err != nil {
				completionErr = errors.New("kubeconfig replay pipe write failed")
			}
		})
		return completionErr
	}
	return complete, nil
}

// Close zeroes the retained kubeconfig. It is safe to call repeatedly.
func (replay *Replay) Close() error {
	if replay == nil {
		return nil
	}
	replay.mu.Lock()
	defer replay.mu.Unlock()
	if replay.closed {
		return nil
	}
	replay.closed = true
	zero(replay.data)
	replay.data = nil
	return nil
}

func restrictedEnvironment(environment []string, kubeconfigFD int) []string {
	return restrictedEnvironmentWithNames(environment, kubeconfigFD, nil)
}

func restrictedEnvironmentWithNames(environment []string, kubeconfigFD int, environmentNames []string) []string {
	clean := make([]string, 0, len(environment)+2)
	for _, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		allowed := name == "PATH" || name == "HOME" || name == "LANG" || name == "SSL_CERT_FILE" || name == "SSL_CERT_DIR" ||
			name == "HTTP_PROXY" || name == "HTTPS_PROXY" || name == "NO_PROXY" || name == "http_proxy" || name == "https_proxy" || name == "no_proxy" ||
			strings.HasPrefix(name, "LC_")
		if allowed || slices.Contains(environmentNames, name) {
			clean = append(clean, entry)
		}
	}
	return append(clean, "GIT_TERMINAL_PROMPT=0", "KUBECONFIG=/dev/fd/"+strconv.Itoa(kubeconfigFD))
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
