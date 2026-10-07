//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package velero118

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
	"github.com/opencloudtech/CloudRING/pkg/kubeconfigpipe"
)

func TestKubectlReaderUsesExactRawAPIPath(t *testing.T) {
	argumentsPath := filepath.Join(t.TempDir(), "arguments")
	object := string(kubeObject(t, "v1", "PersistentVolumeClaim", metadata("volume", "tenant", "uid", "1", nil, map[string]string{}), map[string]any{}, map[string]any{}, nil))
	script := writeExecutable(t, "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$CLOUDRING_ARGUMENTS\"\nprintf '%s' \"$CLOUDRING_RESPONSE\"\n")
	t.Setenv("CLOUDRING_ARGUMENTS", argumentsPath)
	t.Setenv("CLOUDRING_RESPONSE", object)
	reader, err := NewKubectlReader(script)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.Get(t.Context(), restoreproof.CoreV1PVCGVR, "tenant", "volume"); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	// #nosec G304 -- argumentsPath is a test-owned path inside t.TempDir().
	arguments, err := os.ReadFile(argumentsPath)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(string(arguments))
	if got != "get --raw /api/v1/namespaces/tenant/persistentvolumeclaims/volume" || strings.Contains(got, "-o") {
		t.Fatalf("kubectl arguments = %q", got)
	}
}

func TestKubectlReaderWatchUsesExactResourceVersion(t *testing.T) {
	argumentsPath := filepath.Join(t.TempDir(), "arguments")
	configMap := kubeObject(t, "v1", "ConfigMap", metadata("result", "velero", "uid", "11", nil, map[string]string{}), nil, nil, map[string]string{"key": "value"})
	stream := string(mustJSON(t, map[string]any{"type": "ADDED", "object": json.RawMessage(configMap)})) + "\n"
	script := writeExecutable(t, "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$CLOUDRING_ARGUMENTS\"\nprintf '%s' \"$CLOUDRING_RESPONSE\"\n")
	t.Setenv("CLOUDRING_ARGUMENTS", argumentsPath)
	t.Setenv("CLOUDRING_RESPONSE", stream)
	reader, err := NewKubectlReader(script)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	events, resourceVersion, err := reader.WatchPage(t.Context(), restoreproof.CoreV1CMGVR, "velero", "role=result", "10", 5)
	if err != nil || len(events) != 1 || events[0].Type != "ADDED" || resourceVersion != "11" {
		t.Fatalf("WatchPage() = %#v, %q, %v", events, resourceVersion, err)
	}
	// #nosec G304 -- argumentsPath is a test-owned path inside t.TempDir().
	arguments, err := os.ReadFile(argumentsPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(arguments)
	for _, required := range []string{"get --raw /api/v1/namespaces/velero/configmaps?", "watch=true", "allowWatchBookmarks=true", "resourceVersion=10", "timeoutSeconds=5", "labelSelector=role%3Dresult"} {
		if !strings.Contains(got, required) {
			t.Fatalf("watch arguments %q do not contain %q", got, required)
		}
	}
}

func TestDecodeWatchStreamFailsClosedOnExpiredOrMalformedEvents(t *testing.T) {
	validObject := kubeObject(t, "v1", "ConfigMap", metadata("result", "velero", "uid", "11", nil, map[string]string{}), nil, nil, nil)
	valid := mustJSON(t, map[string]any{"type": "ADDED", "object": json.RawMessage(validObject)})
	bookmark := mustJSON(t, map[string]any{"type": "BOOKMARK", "object": map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"resourceVersion": "12"},
	}})
	events, resourceVersion, err := decodeWatchStream(append(append(valid, '\n'), bookmark...), "10")
	if err != nil || len(events) != 1 || resourceVersion != "12" {
		t.Fatalf("valid watch stream = %#v, %q, %v", events, resourceVersion, err)
	}
	expired := mustJSON(t, map[string]any{"type": "ERROR", "object": map[string]any{
		"apiVersion": "v1", "kind": "Status", "reason": "Expired", "code": 410,
	}})
	malformed := mustJSON(t, map[string]any{"type": "ADDED", "object": map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "result"},
	}})
	for name, payload := range map[string][]byte{"expired": expired, "missing resourceVersion": malformed, "invalid JSON": []byte("{")} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeWatchStream(payload, "10"); err == nil {
				t.Fatal("unsafe watch stream unexpectedly passed")
			}
		})
	}
}

func TestExecBackendObserverKeepsRawHandleOnStdin(t *testing.T) {
	inputPath := filepath.Join(t.TempDir(), "input")
	script := writeExecutable(t, "#!/bin/sh\ncat > \"$CLOUDRING_INPUT\"\nprintf '%s' \"$CLOUDRING_RESPONSE\"\n")
	t.Setenv("CLOUDRING_INPUT", inputPath)
	observer, err := NewExecBackendObserver(script)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	handle := "synthetic-provider-handle"
	request := BackendRequest{
		SchemaVersion: AdapterRequestSchemaVersion, RequestDigestCanonicalization: AdapterRequestCanonicalization, Challenge: digest("challenge"), AdapterExecutableSHA256: observer.IdentitySHA256(),
		Operation: "observe", SourceKind: "persistent-volume", ArtifactHandle: handle, ArtifactHandleSHA256: restoreproof.SHA256(handle),
	}
	present := false
	response := BackendObservation{
		SchemaVersion: AdapterResponseSchemaVersion, Implementation: "provider-adapter", Version: "v1", Present: &present,
		RequestSHA256: adapterRequestSHA256(request), AdapterExecutableSHA256: observer.IdentitySHA256(), ArtifactHandleSHA256: request.ArtifactHandleSHA256,
		ObservedAt: "2026-07-14T12:00:00Z", EvidenceRef: "runtime/provider", EvidenceSHA256: digest("evidence"),
	}
	t.Setenv("CLOUDRING_RESPONSE", string(mustJSON(t, response)))
	observer.environment = []string{"CLOUDRING_INPUT=" + inputPath, "CLOUDRING_RESPONSE=" + string(mustJSON(t, response))}
	// The original path changes after construction; execution must continue from
	// the private pinned snapshot and retain the advertised identity.
	// #nosec G306 -- test-only executable in a per-test private directory.
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	observation, err := observer.Observe(t.Context(), request)
	if err != nil || observation.Present == nil || *observation.Present {
		t.Fatalf("Observe() = %#v, %v", observation, err)
	}
	// #nosec G304 -- inputPath is a test-owned path inside t.TempDir().
	input, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(input), handle) {
		t.Fatal("provider handle was not delivered on stdin")
	}
}

func TestExecBackendObserverRejectsUnknownMissingReplayAndInvalidVersion(t *testing.T) {
	script := writeExecutable(t, "#!/bin/sh\ncat >/dev/null\nprintf '%s' \"$CLOUDRING_RESPONSE\"\n")
	observer, err := NewExecBackendObserver(script)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	request := BackendRequest{
		SchemaVersion: AdapterRequestSchemaVersion, RequestDigestCanonicalization: AdapterRequestCanonicalization, Challenge: digest("challenge"), AdapterExecutableSHA256: observer.IdentitySHA256(),
		Operation: "observe", SourceKind: "persistent-volume", ArtifactHandle: "synthetic-handle", ArtifactHandleSHA256: digest("synthetic-handle"),
	}
	present := false
	base := BackendObservation{
		SchemaVersion: AdapterResponseSchemaVersion, Implementation: "provider-adapter", Version: "v1", Present: &present,
		RequestSHA256: adapterRequestSHA256(request), AdapterExecutableSHA256: observer.IdentitySHA256(), ArtifactHandleSHA256: request.ArtifactHandleSHA256,
		ObservedAt: "2026-07-14T12:00:00Z", EvidenceRef: "runtime/provider", EvidenceSHA256: digest("evidence"),
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "unknown field", mutate: func(value map[string]any) { value["unknown"] = true }},
		{name: "missing present", mutate: func(value map[string]any) { delete(value, "present") }},
		{name: "replayed request", mutate: func(value map[string]any) { value["requestSha256"] = digest("old-request") }},
		{name: "invalid version", mutate: func(value map[string]any) { value["version"] = "1.0.0" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			payload := mustJSON(t, base)
			var value map[string]any
			if err := json.Unmarshal(payload, &value); err != nil {
				t.Fatal(err)
			}
			test.mutate(value)
			t.Setenv("CLOUDRING_RESPONSE", string(mustJSON(t, value)))
			observer.environment = []string{"CLOUDRING_RESPONSE=" + string(mustJSON(t, value))}
			if _, err := observer.Observe(t.Context(), request); err == nil {
				t.Fatal("invalid adapter response unexpectedly passed")
			}
		})
	}
}

func TestExecBackendObserverDoesNotInheritAmbientCredentials(t *testing.T) {
	environmentPath := filepath.Join(t.TempDir(), "environment")
	script := writeExecutable(t, "#!/bin/sh\n/usr/bin/env > "+strconv.Quote(environmentPath)+"\nexit 2\n")
	t.Setenv("BW_SESSION", "must-not-reach-adapter")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "must-not-reach-adapter")
	t.Setenv("KUBECONFIG", "must-not-reach-adapter")
	observer, err := NewExecBackendObserver(script)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	request := BackendRequest{
		SchemaVersion: AdapterRequestSchemaVersion, RequestDigestCanonicalization: AdapterRequestCanonicalization, Challenge: digest("challenge"), AdapterExecutableSHA256: observer.IdentitySHA256(),
		Operation: "observe", SourceKind: "persistent-volume", ArtifactHandle: "synthetic-handle", ArtifactHandleSHA256: digest("synthetic-handle"),
	}
	if _, err := observer.Observe(t.Context(), request); err == nil {
		t.Fatal("adapter without a response unexpectedly succeeded")
	}
	// #nosec G304 -- environmentPath is a test-owned path inside t.TempDir().
	payload, err := os.ReadFile(environmentPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(payload)
	if strings.Contains(got, "BW_SESSION=") || strings.Contains(got, "AWS_SECRET_ACCESS_KEY=") || strings.Contains(got, "KUBECONFIG=") {
		t.Fatalf("credential environment reached adapter: %q", got)
	}
}

func TestPinnedCommandTimeoutKillsProcessGroup(t *testing.T) {
	script := writeExecutable(t, "#!/bin/sh\nsleep 30 &\nwait\n")
	executable, err := pinExecutable(script, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	started := time.Now()
	if _, _, err := runCommand(context.Background(), executable, nil, nil, 1024); err == nil {
		t.Fatal("timed out process tree unexpectedly succeeded")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("process-tree timeout was not enforced")
	}
}

func TestSuccessfulPinnedCommandKillsBackgroundProcessGroup(t *testing.T) {
	readyPath, livenessPath, liveness := newBackgroundLivenessProbe(t)
	script := writeExecutable(t, `#!/bin/sh
(
  exec 3>"$2"
  printf r >&3
  : > "$1"
  sleep 300
) </dev/null >/dev/null 2>&1 &
while [ ! -e "$1" ]; do sleep 0.01; done
printf ok
`)
	executable, err := pinExecutable(script, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	output, _, err := runCommand(context.Background(), executable, []string{readyPath, livenessPath}, nil, 1024)
	if err != nil || string(output) != "ok" {
		t.Fatalf("successful command = %q, %v", output, err)
	}
	assertBackgroundResourcesReleased(t, liveness)
}

func TestKubeconfigReplayCannotBlockBackgroundProcessCleanup(t *testing.T) {
	readyPath, livenessPath, liveness := newBackgroundLivenessProbe(t)
	script := writeExecutable(t, `#!/bin/sh
(
  exec 3>"$2"
  printf r >&3
  : > "$1"
  sleep 300
) </dev/null >/dev/null 2>&1 &
while [ ! -e "$1" ]; do sleep 0.01; done
printf ok
`)
	executable, err := pinExecutable(script, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	replay := newKubeconfigReplay(t, bytes.Repeat([]byte{'a'}, 1<<20))
	defer replay.Close()
	started := time.Now()
	if _, _, err := runCommandWithKubeconfig(context.Background(), executable, []string{readyPath, livenessPath}, 1024, replay); err == nil {
		t.Fatal("command that did not consume its kubeconfig unexpectedly succeeded")
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("kubeconfig replay blocked process-tree cleanup")
	}
	assertBackgroundResourcesReleased(t, liveness)
}

func newBackgroundLivenessProbe(t *testing.T) (string, string, *os.File) {
	t.Helper()
	dir := t.TempDir()
	livenessPath := filepath.Join(dir, "background-liveness")
	if err := syscall.Mkfifo(livenessPath, 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- livenessPath is a test-owned FIFO inside t.TempDir().
	liveness, err := os.OpenFile(livenessPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = liveness.Close() })
	return filepath.Join(dir, "background-ready"), livenessPath, liveness
}

func assertBackgroundResourcesReleased(t *testing.T, liveness *os.File) {
	t.Helper()
	// A killed zombie can still retain a PID on Unix. FIFO EOF instead proves
	// that the background process cannot execute or retain command resources.
	deadline := time.Now().Add(5 * time.Second)
	buffer := make([]byte, 1)
	observedReady := false
	for time.Now().Before(deadline) {
		count, err := liveness.Read(buffer)
		if count == 1 {
			if observedReady || buffer[0] != 'r' {
				t.Fatalf("unexpected background liveness payload %q", buffer[:count])
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
		t.Fatal("background process did not establish its liveness descriptor before cleanup")
	}
	t.Fatal("background process retained a live resource after process-group cleanup")
}

func newKubeconfigReplay(t *testing.T, data []byte) *kubeconfigpipe.Replay {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := writer.Write(data)
		closeErr := writer.Close()
		if writeErr != nil {
			writeDone <- writeErr
			return
		}
		writeDone <- closeErr
	}()
	replay, err := kubeconfigpipe.NewFromFD(int(reader.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	return replay
}

func TestAdapterErrorsDoNotReflectChildOutput(t *testing.T) {
	script := writeExecutable(t, "#!/bin/sh\nprintf 'private-child-value' >&2\nexit 1\n")
	observer, err := NewExecBackendObserver(script)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	_, err = observer.Observe(t.Context(), BackendRequest{
		SchemaVersion: AdapterRequestSchemaVersion, RequestDigestCanonicalization: AdapterRequestCanonicalization, Challenge: digest("challenge"), AdapterExecutableSHA256: observer.IdentitySHA256(), Operation: "observe", SourceKind: "persistent-volume",
		ArtifactHandle: "synthetic-handle", ArtifactHandleSHA256: restoreproof.SHA256("synthetic-handle"),
	})
	if err == nil || strings.Contains(err.Error(), "private-child-value") {
		t.Fatalf("sanitized error = %v", err)
	}
}

func writeExecutable(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "adapter")
	// #nosec G306 -- test-only executable in a per-test private directory.
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
