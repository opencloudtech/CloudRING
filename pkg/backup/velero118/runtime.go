// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package velero118

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
	"github.com/opencloudtech/CloudRING/pkg/kubeconfigpipe"
	"github.com/opencloudtech/CloudRING/pkg/secureexec"
)

const (
	maxAdapterResponseBytes = 64 << 10
	defaultKubectlTimeout   = 2 * time.Minute
	defaultProbeTimeout     = 30 * time.Minute
	defaultBackendTimeout   = 2 * time.Minute
)

// KubectlReader uses kubectl's raw API path so discovery cannot silently select
// a different served version. It performs read-only GET requests.
type KubectlReader struct {
	executable *secureexec.Executable
	kubeconfig *kubeconfigpipe.Replay
}

func NewKubectlReader(binary string) (*KubectlReader, error) {
	return newKubectlReader(binary, nil)
}

// NewKubectlReaderFromKubeconfigFD consumes one pipe-backed kubeconfig from fd
// and replays it through a fresh anonymous pipe for every kubectl invocation.
// This supports multi-query collectors without ever persisting kubeconfig
// bytes or exposing them through argv or the child environment.
func NewKubectlReaderFromKubeconfigFD(binary string, fd int) (*KubectlReader, error) {
	reader, err := newKubectlReader(binary, nil)
	if err != nil {
		return nil, err
	}
	replay, err := kubeconfigpipe.NewFromFD(fd)
	if err != nil {
		_ = reader.Close()
		return nil, err
	}
	reader.kubeconfig = replay
	return reader, nil
}

func newKubectlReader(binary string, replay *kubeconfigpipe.Replay) (*KubectlReader, error) {
	if strings.TrimSpace(binary) == "" {
		binary = "kubectl"
	}
	executable, err := secureexec.Pin(binary, defaultKubectlTimeout)
	if err != nil {
		return nil, errors.New("pin kubectl executable")
	}
	return &KubectlReader{executable: executable, kubeconfig: replay}, nil
}

func (reader *KubectlReader) Close() error {
	if reader == nil {
		return nil
	}
	var executableErr error
	if reader.executable != nil {
		executableErr = reader.executable.Close()
	}
	return errors.Join(executableErr, reader.kubeconfig.Close())
}

func (reader *KubectlReader) run(ctx context.Context, arguments []string, maximum int64) ([]byte, []byte, error) {
	if reader == nil || reader.executable == nil {
		return nil, nil, errors.New("kubectl reader is closed")
	}
	if reader.kubeconfig == nil {
		return runCommand(ctx, reader.executable, arguments, nil, maximum)
	}
	return runCommandWithKubeconfig(ctx, reader.executable, arguments, maximum, reader.kubeconfig)
}

func (reader *KubectlReader) Get(ctx context.Context, gvr restoreproof.GVR, namespace, name string) ([]byte, error) {
	if reader == nil || reader.executable == nil || !safeGVR(gvr) || namespace != "" && !safeName(namespace) || !safeName(name) {
		return nil, errors.New("invalid Kubernetes object read")
	}
	path := rawResourcePath(gvr, namespace) + "/" + url.PathEscape(name)
	output, stderr, err := reader.run(ctx, []string{"get", "--raw", path}, strictjson.MaxDocumentBytes)
	defer zeroBytes(stderr)
	if err != nil {
		notFound := possibleNotFound(output, stderr)
		zeroBytes(output)
		if notFound {
			return nil, ErrNotFound
		}
		return nil, errors.New("Kubernetes raw object read failed")
	}
	if err := strictjson.Validate(output); err != nil {
		return nil, errors.New("Kubernetes raw object response is invalid")
	}
	return output, nil
}

func (reader *KubectlReader) ListPage(ctx context.Context, gvr restoreproof.GVR, namespace, selector, continueToken string, limit int) ([]byte, error) {
	if reader == nil || reader.executable == nil || !safeGVR(gvr) || namespace != "" && !safeName(namespace) || limit <= 0 || limit > 1000 || len(selector) > 2048 || len(continueToken) > 8192 {
		return nil, errors.New("invalid Kubernetes list read")
	}
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	if selector != "" {
		query.Set("labelSelector", selector)
	}
	if continueToken != "" {
		query.Set("continue", continueToken)
	}
	path := rawResourcePath(gvr, namespace) + "?" + query.Encode()
	output, stderr, err := reader.run(ctx, []string{"get", "--raw", path}, strictjson.MaxDocumentBytes)
	defer zeroBytes(stderr)
	if err != nil {
		zeroBytes(output)
		return nil, errors.New("Kubernetes raw list read failed")
	}
	if err := strictjson.Validate(output); err != nil {
		return nil, errors.New("Kubernetes raw list response is invalid")
	}
	return output, nil
}

// WatchPage resumes a raw Kubernetes watch from an exact list resourceVersion.
// The API timeout bounds each stream; callers resume from the returned
// resourceVersion. An expired or malformed stream fails closed instead of
// relisting over a potential observation gap.
func (reader *KubectlReader) WatchPage(ctx context.Context, gvr restoreproof.GVR, namespace, selector, resourceVersion string, timeoutSeconds int) ([]WatchEvent, string, error) {
	if reader == nil || reader.executable == nil || !safeGVR(gvr) || namespace != "" && !safeName(namespace) || len(selector) > 2048 ||
		resourceVersion == "" || len(resourceVersion) > 256 || timeoutSeconds < 1 || timeoutSeconds > 30 {
		return nil, "", errors.New("invalid Kubernetes watch read")
	}
	query := url.Values{}
	query.Set("watch", "true")
	query.Set("allowWatchBookmarks", "true")
	query.Set("resourceVersion", resourceVersion)
	query.Set("timeoutSeconds", strconv.Itoa(timeoutSeconds))
	if selector != "" {
		query.Set("labelSelector", selector)
	}
	path := rawResourcePath(gvr, namespace) + "?" + query.Encode()
	output, stderr, err := reader.run(ctx, []string{"get", "--raw", path}, strictjson.MaxDocumentBytes)
	defer zeroBytes(stderr)
	if err != nil {
		zeroBytes(output)
		return nil, "", errors.New("Kubernetes raw watch failed")
	}
	defer zeroBytes(output)
	events, lastResourceVersion, err := decodeWatchStream(output, resourceVersion)
	if err != nil {
		return nil, "", err
	}
	return events, lastResourceVersion, nil
}

func decodeWatchStream(payload []byte, initialResourceVersion string) ([]WatchEvent, string, error) {
	if len(payload) > strictjson.MaxDocumentBytes {
		return nil, "", errors.New("Kubernetes watch stream is oversized")
	}
	lastResourceVersion := initialResourceVersion
	lines := bytes.Split(payload, []byte{'\n'})
	events := make([]WatchEvent, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if len(events) >= 4096 || strictjson.Validate(line) != nil {
			return nil, "", errors.New("Kubernetes watch event is invalid")
		}
		var envelope struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		if strictjson.Decode(line, &envelope) != nil || len(envelope.Object) == 0 {
			return nil, "", errors.New("Kubernetes watch envelope is invalid")
		}
		if envelope.Type == "ERROR" {
			var status struct {
				APIVersion string `json:"apiVersion"`
				Kind       string `json:"kind"`
				Reason     string `json:"reason"`
				Code       int    `json:"code"`
			}
			if strictjson.Decode(envelope.Object, &status) == nil && status.APIVersion == "v1" && status.Kind == "Status" && (status.Code == 410 || status.Reason == "Expired") {
				return nil, "", errors.New("Kubernetes watch resourceVersion expired")
			}
			return nil, "", errors.New("Kubernetes watch returned an error event")
		}
		if envelope.Type != "ADDED" && envelope.Type != "MODIFIED" && envelope.Type != "DELETED" && envelope.Type != "BOOKMARK" {
			return nil, "", errors.New("Kubernetes watch event type is invalid")
		}
		var metadataOnly struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
		}
		if strictjson.Decode(envelope.Object, &metadataOnly) != nil || metadataOnly.Metadata.ResourceVersion == "" {
			return nil, "", errors.New("Kubernetes watch resourceVersion is missing")
		}
		lastResourceVersion = metadataOnly.Metadata.ResourceVersion
		if envelope.Type != "BOOKMARK" {
			events = append(events, WatchEvent{Type: envelope.Type, Object: append([]byte(nil), envelope.Object...)})
		}
	}
	return events, lastResourceVersion, nil
}

// ConfirmAbsent proves an exact-object 404 against a successful list of the
// same collection. A proxy or wrong-GVR 404 therefore cannot satisfy cleanup.
func (reader *KubectlReader) ConfirmAbsent(ctx context.Context, gvr restoreproof.GVR, namespace, name string) (bool, error) {
	apiVersion, kind, ok := exactListGVK(gvr)
	if reader == nil || reader.executable == nil || !ok || namespace != "" && !safeName(namespace) || !safeName(name) {
		return false, errors.New("invalid Kubernetes absence confirmation")
	}
	query := url.Values{}
	query.Set("fieldSelector", "metadata.name="+name)
	query.Set("limit", "2")
	path := rawResourcePath(gvr, namespace) + "?" + query.Encode()
	output, stderr, err := reader.run(ctx, []string{"get", "--raw", path}, strictjson.MaxDocumentBytes)
	defer zeroBytes(stderr)
	if err != nil {
		zeroBytes(output)
		return false, errors.New("Kubernetes exact collection read failed")
	}
	defer zeroBytes(output)
	page, err := DecodeListPage(output, apiVersion, kind)
	if err != nil || page.Continue != "" || len(page.Items) > 1 {
		return false, errors.New("Kubernetes exact collection response is invalid")
	}
	if len(page.Items) == 0 {
		return true, nil
	}
	var envelope objectEnvelope
	if strictjson.Decode(page.Items[0], &envelope) != nil || envelope.Metadata.Namespace != namespace || envelope.Metadata.Name != name {
		return false, errors.New("Kubernetes exact collection identity is invalid")
	}
	return false, nil
}

func exactListGVK(gvr restoreproof.GVR) (string, string, bool) {
	switch gvr {
	case restoreproof.CoreV1PVCGVR:
		return "v1", "PersistentVolumeClaimList", true
	case restoreproof.CoreV1PVGVR:
		return "v1", "PersistentVolumeList", true
	case restoreproof.CoreV1CMGVR:
		return "v1", "ConfigMapList", true
	case restoreproof.VeleroV1RestoreGVR:
		return "velero.io/v1", "RestoreList", true
	case restoreproof.DataDownloadGVR:
		return "velero.io/v2alpha1", "DataDownloadList", true
	default:
		return "", "", false
	}
}

func possibleNotFound(output, stderr []byte) bool {
	for _, payload := range [][]byte{output, stderr} {
		var status struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Reason     string `json:"reason"`
			Code       int    `json:"code"`
		}
		if strictjson.Decode(payload, &status) == nil && status.APIVersion == "v1" && status.Kind == "Status" && status.Reason == "NotFound" && status.Code == 404 {
			return true
		}
	}
	return bytes.Contains(stderr, []byte("(NotFound)"))
}

// ExecProbeObserver invokes a downstream read-only probe adapter. Object refs
// enter through stdin and adapter stderr is never reflected. Ambient
// credentials are removed; an optional kubeconfig is replayed through a fresh
// anonymous descriptor for each invocation.
type ExecProbeObserver struct {
	executable  *secureexec.Executable
	environment []string
	kubeconfig  *kubeconfigpipe.Replay
}

func NewExecProbeObserver(path string) (*ExecProbeObserver, error) {
	return newExecProbeObserver(path, nil, restrictedAdapterEnvironment(os.Environ()))
}

// NewExecProbeObserverForKubectlReader shares only the reader's anonymous
// kubeconfig replay with the adapter; it never exposes the parent credential
// environment.
func NewExecProbeObserverForKubectlReader(path string, reader *KubectlReader) (*ExecProbeObserver, error) {
	if reader == nil {
		return nil, errors.New("data probe Kubernetes reader is missing")
	}
	return newExecProbeObserver(path, reader.kubeconfig, restrictedAdapterEnvironment(os.Environ()))
}

func newExecProbeObserver(path string, kubeconfig *kubeconfigpipe.Replay, environment []string) (*ExecProbeObserver, error) {
	executable, err := secureexec.PinAbsolute(path, defaultProbeTimeout)
	if err != nil {
		return nil, errors.New("pin data probe adapter")
	}
	return &ExecProbeObserver{executable: executable, environment: append([]string(nil), environment...), kubeconfig: kubeconfig}, nil
}

func (observer *ExecProbeObserver) IdentitySHA256() string {
	if observer == nil || observer.executable == nil {
		return ""
	}
	return observer.executable.IdentitySHA256()
}

func (observer *ExecProbeObserver) Close() error {
	if observer == nil || observer.executable == nil {
		return nil
	}
	return observer.executable.Close()
}

func (observer *ExecProbeObserver) Observe(ctx context.Context, request ProbeRequest) (ProbeObservation, error) {
	if observer == nil || observer.executable == nil || request.SchemaVersion != AdapterRequestSchemaVersion || request.RequestDigestCanonicalization != AdapterRequestCanonicalization || !validSHA256(request.Challenge) ||
		request.AdapterExecutableSHA256 != observer.IdentitySHA256() {
		return ProbeObservation{}, errors.New("invalid data probe adapter invocation")
	}
	input, err := json.Marshal(request)
	if err != nil {
		return ProbeObservation{}, errors.New("encode data probe request")
	}
	requestSHA256 := adapterRequestSHA256(request)
	output, childError, err := observer.executable.RunWithEnvironment(ctx, nil, input, maxAdapterResponseBytes, 64<<10, observer.environment, observer.kubeconfig)
	zeroBytes(input)
	zeroBytes(childError)
	if err != nil {
		zeroBytes(output)
		return ProbeObservation{}, errors.New("data probe adapter failed")
	}
	defer zeroBytes(output)
	var observation ProbeObservation
	if err := strictjson.DecodeExact(output, &observation); err != nil || !validProbeObservation(observation) ||
		observation.RequestSHA256 != requestSHA256 || observation.AdapterExecutableSHA256 != observer.IdentitySHA256() {
		return ProbeObservation{}, errors.New("data probe adapter response is invalid")
	}
	return observation, nil
}

// ExecBackendObserver invokes a provider adapter with the raw handle only on
// stdin. The handle is zeroed from the request buffer after execution and
// ambient credentials are never inherited.
type ExecBackendObserver struct {
	executable  *secureexec.Executable
	environment []string
}

func NewExecBackendObserver(path string) (*ExecBackendObserver, error) {
	return newExecBackendObserver(path, restrictedAdapterEnvironment(os.Environ()))
}

func newExecBackendObserver(path string, environment []string) (*ExecBackendObserver, error) {
	executable, err := secureexec.PinAbsolute(path, defaultBackendTimeout)
	if err != nil {
		return nil, errors.New("pin provider observer adapter")
	}
	return &ExecBackendObserver{executable: executable, environment: append([]string(nil), environment...)}, nil
}

func (observer *ExecBackendObserver) IdentitySHA256() string {
	if observer == nil || observer.executable == nil {
		return ""
	}
	return observer.executable.IdentitySHA256()
}

func (observer *ExecBackendObserver) Close() error {
	if observer == nil || observer.executable == nil {
		return nil
	}
	return observer.executable.Close()
}

func (observer *ExecBackendObserver) Observe(ctx context.Context, request BackendRequest) (BackendObservation, error) {
	if observer == nil || observer.executable == nil || request.SchemaVersion != AdapterRequestSchemaVersion || request.RequestDigestCanonicalization != AdapterRequestCanonicalization || !validSHA256(request.Challenge) ||
		request.AdapterExecutableSHA256 != observer.IdentitySHA256() || request.Operation != "observe" || request.SourceKind != "persistent-volume" ||
		request.ArtifactHandle == "" || restoreproof.SHA256(request.ArtifactHandle) != request.ArtifactHandleSHA256 {
		return BackendObservation{}, errors.New("invalid provider observer invocation")
	}
	input, err := json.Marshal(request)
	if err != nil {
		return BackendObservation{}, errors.New("encode provider observation request")
	}
	requestSHA256 := adapterRequestSHA256(request)
	output, childError, err := observer.executable.RunWithEnvironment(ctx, nil, input, maxAdapterResponseBytes, 64<<10, observer.environment, nil)
	zeroBytes(input)
	zeroBytes(childError)
	if err != nil {
		zeroBytes(output)
		return BackendObservation{}, errors.New("provider observer adapter failed")
	}
	defer zeroBytes(output)
	var observation BackendObservation
	if err := strictjson.DecodeExact(output, &observation); err != nil || !validBackendObservation(observation) ||
		observation.RequestSHA256 != requestSHA256 || observation.AdapterExecutableSHA256 != observer.IdentitySHA256() ||
		observation.ArtifactHandleSHA256 != request.ArtifactHandleSHA256 {
		return BackendObservation{}, errors.New("provider observer adapter response is invalid")
	}
	return observation, nil
}

func rawResourcePath(gvr restoreproof.GVR, namespace string) string {
	var base string
	if gvr.Group == "" {
		base = "/api/" + url.PathEscape(gvr.Version)
	} else {
		base = "/apis/" + url.PathEscape(gvr.Group) + "/" + url.PathEscape(gvr.Version)
	}
	if namespace != "" {
		base += "/namespaces/" + url.PathEscape(namespace)
	}
	return base + "/" + url.PathEscape(gvr.Resource)
}

func safeGVR(gvr restoreproof.GVR) bool {
	return (gvr.Group == "" || safeAPISegment(gvr.Group)) && safeAPISegment(gvr.Version) && safeAPISegment(gvr.Resource)
}

func safeAPISegment(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/\\?&#%\x00\t\r\n ") {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '.') {
			return false
		}
	}
	return true
}

type pinnedExecutable = secureexec.Executable

func pinExecutable(path string, timeout time.Duration) (*pinnedExecutable, error) {
	return secureexec.PinAbsolute(path, timeout)
}

func runCommand(ctx context.Context, executable *pinnedExecutable, arguments []string, input []byte, maximum int64) ([]byte, []byte, error) {
	if executable == nil {
		return nil, nil, errors.New("command executable is missing")
	}
	return executable.Run(ctx, arguments, input, maximum, 64<<10, nil)
}

func runCommandWithKubeconfig(ctx context.Context, executable *pinnedExecutable, arguments []string, maximum int64, kubeconfig *kubeconfigpipe.Replay) ([]byte, []byte, error) {
	if executable == nil || kubeconfig == nil {
		return nil, nil, errors.New("pipe-backed command is incomplete")
	}
	return executable.Run(ctx, arguments, nil, maximum, 64<<10, kubeconfig)
}

func restrictedAdapterEnvironment(environment []string) []string {
	clean := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		allowed := name == "PATH" || name == "LANG" || name == "SSL_CERT_FILE" || name == "SSL_CERT_DIR" || strings.HasPrefix(name, "LC_")
		if allowed {
			clean = append(clean, entry)
		}
	}
	return append(clean, "GIT_TERMINAL_PROMPT=0")
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
