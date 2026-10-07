//go:build unix

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package secureexec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/kubeconfigpipe"
)

const fastExecutableTestTimeout = 10 * time.Second

func TestPinnedExecutableIgnoresLaterPATHReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kubectl")
	writeExecutable(t, path, "#!/bin/sh\ncat \"$KUBECONFIG\" >/dev/null\nprintf first\n")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	executable, err := Pin("kubectl", fastExecutableTestTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	writeExecutable(t, path, "#!/bin/sh\ncat \"$KUBECONFIG\" >/dev/null\nprintf replacement\n")
	replay := newReplay(t, []byte("apiVersion: v1\n"))
	defer replay.Close()
	stdout, stderr, err := executable.Run(context.Background(), nil, nil, 1024, 1024, replay)
	defer zero(stdout)
	defer zero(stderr)
	if err != nil || string(stdout) != "first" || len(stderr) != 0 {
		t.Fatalf("pinned execution = %q, stderr=%q, err=%v", stdout, stderr, err)
	}
}

func TestPinnedExecutableBoundsCapturedOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adapter")
	writeExecutable(t, path, "#!/bin/sh\nprintf 0123456789abcdef\n")
	executable, err := PinAbsolute(path, fastExecutableTestTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	stdout, stderr, err := executable.Run(context.Background(), nil, nil, 8, 8, nil)
	zero(stdout)
	zero(stderr)
	if err == nil || len(stdout) != 0 || len(stderr) != 0 {
		t.Fatalf("oversized output = stdout:%d stderr:%d err:%v", len(stdout), len(stderr), err)
	}
	if _, _, err := executable.Run(context.Background(), nil, nil, maxCapturedOutputBytes+1, 8, nil); err == nil {
		t.Fatal("unbounded capture limit unexpectedly passed")
	}
}

func TestPinnedExecutablePreservesBoundedCommandFailureDiagnostics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adapter")
	writeExecutable(t, path, "#!/bin/sh\nprintf missing >&2\nexit 2\n")
	executable, err := PinAbsolute(path, fastExecutableTestTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	stdout, stderr, err := executable.Run(context.Background(), nil, nil, 64, 64, nil)
	defer zero(stdout)
	defer zero(stderr)
	if err == nil || len(stdout) != 0 || string(stderr) != "missing" {
		t.Fatalf("command failure = stdout:%q stderr:%q err:%v", stdout, stderr, err)
	}
}

func TestPinnedExecutableAllowsConcurrentReplayRuns(t *testing.T) {
	dir := t.TempDir()
	markerDir := filepath.Join(dir, "markers")
	if err := os.Mkdir(markerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "kubectl")
	writeExecutable(t, path, `#!/bin/sh
set -eu
cat "$KUBECONFIG" >/dev/null
: > "$1/$2"
attempt=0
while [ "$(find "$1" -type f | wc -l | tr -d ' ')" -lt "$3" ]; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 100 ] || exit 94
  sleep 0.02
done
printf overlap-ok
`)
	executable, err := PinAbsolute(path, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	replay := newReplay(t, []byte("apiVersion: v1\n"))
	defer replay.Close()

	const invocations = 4
	var wait sync.WaitGroup
	errorsByInvocation := make([]error, invocations)
	for invocation := range invocations {
		wait.Add(1)
		go func() {
			defer wait.Done()
			stdout, stderr, runErr := executable.Run(
				context.Background(),
				[]string{markerDir, strconv.Itoa(invocation), strconv.Itoa(invocations)},
				nil,
				1024,
				1024,
				replay,
			)
			defer zero(stdout)
			defer zero(stderr)
			if runErr != nil || string(stdout) != "overlap-ok" || len(stderr) != 0 {
				errorsByInvocation[invocation] = errors.New("concurrent pinned replay invocation failed")
			}
		}()
	}
	wait.Wait()
	for invocation, err := range errorsByInvocation {
		if err != nil {
			t.Fatalf("invocation %d: %v", invocation, err)
		}
	}
}

func TestPinnedReplayKillsDescendantHoldingOutputAndKubeconfig(t *testing.T) {
	readyPath, livenessPath, liveness := newDescendantLivenessProbe(t)
	scriptPath := filepath.Join(t.TempDir(), "kubectl")
	writeExecutable(t, scriptPath, `#!/bin/sh
cat "$KUBECONFIG" >/dev/null
(
  exec 3>"$2"
  printf r >&3
  : > "$1"
  sleep 300
) &
while [ ! -e "$1" ]; do sleep 0.01; done
printf ok
`)
	executable, err := PinAbsolute(scriptPath, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	replay := newReplay(t, bytes.Repeat([]byte{'a'}, 1<<20))
	defer replay.Close()
	started := time.Now()
	stdout, stderr, err := executable.Run(context.Background(), []string{readyPath, livenessPath}, nil, 1024, 1024, replay)
	if err == nil {
		t.Fatal("descendant retaining command descriptors unexpectedly passed")
	}
	if len(stdout) != 0 || len(stderr) != 0 {
		t.Fatal("lifecycle failure returned untrusted child output")
	}
	if time.Since(started) > 8*time.Second {
		t.Fatal("descendant cleanup exceeded the bounded wait")
	}
	assertDescendantResourcesReleased(t, liveness)
}

func TestPinnedUnreadReplayCannotBlockDescendantCleanup(t *testing.T) {
	readyPath, livenessPath, liveness := newDescendantLivenessProbe(t)
	scriptPath := filepath.Join(t.TempDir(), "kubectl")
	writeExecutable(t, scriptPath, `#!/bin/sh
(
  exec 3>"$2"
  printf r >&3
  : > "$1"
  sleep 300
) &
while [ ! -e "$1" ]; do sleep 0.01; done
printf ok
`)
	executable, err := PinAbsolute(scriptPath, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	replay := newReplay(t, bytes.Repeat([]byte{'a'}, 1<<20))
	defer replay.Close()
	started := time.Now()
	stdout, stderr, err := executable.Run(context.Background(), []string{readyPath, livenessPath}, nil, 1024, 1024, replay)
	if err == nil {
		t.Fatal("command that ignored kubeconfig unexpectedly passed")
	}
	if len(stdout) != 0 || len(stderr) != 0 {
		t.Fatal("replay lifecycle failure returned untrusted child output")
	}
	if time.Since(started) > 8*time.Second {
		t.Fatal("unread replay blocked descendant cleanup")
	}
	assertDescendantResourcesReleased(t, liveness)
}

func writeExecutable(t *testing.T, path, script string) {
	t.Helper()
	// #nosec G306 -- the test-owned file must be executable and is created inside t.TempDir().
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}

func newReplay(t *testing.T, data []byte) *kubeconfigpipe.Replay {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := writer.Write(data)
		writeDone <- errors.Join(writeErr, writer.Close())
	}()
	replay, err := kubeconfigpipe.NewFromFD(int(reader.Fd()))
	closeErr := reader.Close()
	writeErr := <-writeDone
	if err != nil || closeErr != nil || writeErr != nil {
		t.Fatalf("create replay: read=%v close=%v write=%v", err, closeErr, writeErr)
	}
	return replay
}

func newDescendantLivenessProbe(t *testing.T) (string, string, *os.File) {
	t.Helper()
	dir := t.TempDir()
	livenessPath := filepath.Join(dir, "descendant-liveness")
	if err := syscall.Mkfifo(livenessPath, 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- livenessPath is a test-owned FIFO inside t.TempDir().
	liveness, err := os.OpenFile(livenessPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = liveness.Close() })
	return filepath.Join(dir, "descendant-ready"), livenessPath, liveness
}

func assertDescendantResourcesReleased(t *testing.T, liveness *os.File) {
	t.Helper()
	// A killed zombie can still retain a PID on Unix. FIFO EOF instead proves
	// that the descendant cannot execute or retain command resources.
	deadline := time.Now().Add(5 * time.Second)
	buffer := make([]byte, 1)
	observedReady := false
	for time.Now().Before(deadline) {
		count, err := liveness.Read(buffer)
		if count == 1 {
			if observedReady || buffer[0] != 'r' {
				t.Fatalf("unexpected descendant liveness payload %q", buffer[:count])
			}
			observedReady = true
			continue
		}
		if observedReady && (err == nil || errors.Is(err, io.EOF)) {
			return
		}
		if err != nil && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !observedReady {
		t.Fatal("descendant did not establish its liveness descriptor before cleanup")
	}
	t.Fatal("descendant retained a live resource after process-group cleanup")
}
