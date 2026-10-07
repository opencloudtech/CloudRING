// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/kubeconfigpipe"
	"github.com/opencloudtech/CloudRING/pkg/resilience/oneserverloss"
	"github.com/opencloudtech/CloudRING/pkg/secureexec"
)

const (
	kubectlTimeout     = 90 * time.Second
	probeTimeout       = 2 * time.Minute
	maximumReadyZBytes = 64 << 10
	maximumProbeBytes  = 64 << 10
)

type kubectlReader struct {
	executable *secureexec.Executable
	replay     *kubeconfigpipe.Replay
}

func newKubectlReader(path string, kubeconfigFD int) (*kubectlReader, error) {
	executable, err := secureexec.Pin(path, kubectlTimeout)
	if err != nil {
		return nil, errors.New("pin kubectl executable")
	}
	replay, err := kubeconfigpipe.NewFromFD(kubeconfigFD)
	if err != nil {
		_ = executable.Close()
		return nil, errors.New("read pipe-backed kubeconfig")
	}
	return &kubectlReader{executable: executable, replay: replay}, nil
}

func (reader *kubectlReader) IdentitySHA256() string {
	if reader == nil || reader.executable == nil {
		return ""
	}
	return reader.executable.IdentitySHA256()
}

func (reader *kubectlReader) Close() error {
	if reader == nil {
		return nil
	}
	var executableErr error
	if reader.executable != nil {
		executableErr = reader.executable.Close()
	}
	var replayErr error
	if reader.replay != nil {
		replayErr = reader.replay.Close()
	}
	return errors.Join(executableErr, replayErr)
}

func (reader *kubectlReader) ListPage(ctx context.Context, resource oneserverloss.Resource, namespace, selector, continuation string, limit int) ([]byte, error) {
	if !validResource(resource) || namespace != "" && !validPathName(namespace) || len(selector) > 2048 || len(continuation) > 8192 || limit < 1 || limit > 1000 {
		return nil, errors.New("invalid Kubernetes list request")
	}
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	if selector != "" {
		query.Set("labelSelector", selector)
	}
	if continuation != "" {
		query.Set("continue", continuation)
	}
	path := rawResourcePath(resource, namespace) + "?" + query.Encode()
	output, stderr, err := reader.executable.Run(ctx, []string{"get", "--raw", path}, nil, strictjson.MaxDocumentBytes, maximumReadyZBytes, reader.replay)
	defer zero(stderr)
	if err != nil {
		zero(output)
		return nil, errors.New("Kubernetes raw list read failed")
	}
	if strictjson.Validate(output) != nil {
		zero(output)
		return nil, errors.New("Kubernetes raw list response is invalid")
	}
	return output, nil
}

func (reader *kubectlReader) Get(ctx context.Context, resource oneserverloss.Resource, namespace, name string) ([]byte, error) {
	if !validResource(resource) || namespace != "" && !validPathName(namespace) || !validPathName(name) {
		return nil, errors.New("invalid Kubernetes object request")
	}
	path := rawResourcePath(resource, namespace) + "/" + url.PathEscape(name)
	output, stderr, err := reader.executable.Run(ctx, []string{"get", "--raw", path}, nil, strictjson.MaxDocumentBytes, maximumReadyZBytes, reader.replay)
	if err != nil {
		notFound := kubernetesNotFound(output) || kubernetesNotFound(stderr)
		zero(output)
		zero(stderr)
		if notFound {
			return nil, oneserverloss.ErrNotFound
		}
		return nil, errors.New("Kubernetes raw object read failed")
	}
	zero(stderr)
	if strictjson.Validate(output) != nil {
		zero(output)
		return nil, errors.New("Kubernetes raw object response is invalid")
	}
	return output, nil
}

func (reader *kubectlReader) ReadyZ(ctx context.Context) error {
	output, stderr, err := reader.executable.Run(ctx, []string{"get", "--raw", "/readyz?verbose"}, nil, maximumReadyZBytes, maximumReadyZBytes, reader.replay)
	defer zero(output)
	defer zero(stderr)
	if err != nil || len(output) == 0 || !utf8.Valid(output) || bytes.IndexByte(output, 0) >= 0 {
		return errors.New("Kubernetes readyz read failed")
	}
	foundEtcd := false
	last := ""
	for _, rawLine := range strings.Split(string(output), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		last = line
		if strings.HasPrefix(line, "[-]") {
			return errors.New("Kubernetes readyz check failed")
		}
		if line == "[+]etcd ok" {
			foundEtcd = true
		}
	}
	if !foundEtcd || last != "readyz check passed" {
		return errors.New("Kubernetes readyz response is incomplete")
	}
	return nil
}

func rawResourcePath(resource oneserverloss.Resource, namespace string) string {
	base := "/api/" + url.PathEscape(resource.Version)
	if resource.Group != "" {
		base = "/apis/" + url.PathEscape(resource.Group) + "/" + url.PathEscape(resource.Version)
	}
	if namespace != "" {
		base += "/namespaces/" + url.PathEscape(namespace)
	}
	return base + "/" + url.PathEscape(resource.Resource)
}

func validResource(resource oneserverloss.Resource) bool {
	return safePathPart(resource.Version) && safePathPart(resource.Resource) && resource.Group == "" ||
		safePathPart(resource.Version) && safePathPart(resource.Resource) && safePathPart(resource.Group)
}

func safePathPart(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/\\?&#\x00\r\n") {
		return false
	}
	for _, char := range value {
		if char != '.' && char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func validPathName(value string) bool {
	return value != "" && len(value) <= 253 && filepath.Base(value) == value && !strings.ContainsAny(value, "/\\?&#\x00\r\n")
}

func kubernetesNotFound(payload []byte) bool {
	var status struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Reason     string `json:"reason"`
		Code       int    `json:"code"`
	}
	return strictjson.Decode(payload, &status) == nil && status.APIVersion == "v1" && status.Kind == "Status" && status.Reason == "NotFound" && status.Code == 404 ||
		bytes.Contains(payload, []byte("(NotFound)"))
}

type execProbe struct {
	executable  *secureexec.Executable
	replay      *kubeconfigpipe.Replay
	environment []string
}

func newExecProbe(path string, replay *kubeconfigpipe.Replay) (*execProbe, error) {
	if !filepath.IsAbs(path) || replay == nil {
		return nil, errors.New("data-probe adapter path or kubeconfig is invalid")
	}
	executable, err := secureexec.PinAbsolute(path, probeTimeout)
	if err != nil {
		return nil, errors.New("pin data-probe adapter")
	}
	return &execProbe{executable: executable, replay: replay, environment: restrictedEnvironment(os.Environ())}, nil
}

func (probe *execProbe) IdentitySHA256() string {
	if probe == nil || probe.executable == nil {
		return ""
	}
	return probe.executable.IdentitySHA256()
}

func (probe *execProbe) Close() error {
	if probe == nil || probe.executable == nil {
		return nil
	}
	return probe.executable.Close()
}

func (probe *execProbe) Observe(ctx context.Context, request oneserverloss.ProbeRequest) (oneserverloss.ProbeResponse, error) {
	if probe == nil || probe.executable == nil || request.AdapterExecutableSHA256 != probe.IdentitySHA256() {
		return oneserverloss.ProbeResponse{}, errors.New("invalid data-probe invocation")
	}
	input, err := json.Marshal(request)
	if err != nil {
		return oneserverloss.ProbeResponse{}, errors.New("encode data-probe request")
	}
	defer zero(input)
	output, stderr, err := probe.executable.RunWithEnvironment(ctx, nil, input, maximumProbeBytes, maximumProbeBytes, probe.environment, probe.replay)
	defer zero(output)
	defer zero(stderr)
	if err != nil {
		return oneserverloss.ProbeResponse{}, errors.New("data-probe adapter failed")
	}
	var response oneserverloss.ProbeResponse
	if strictjson.DecodeExact(output, &response) != nil {
		return oneserverloss.ProbeResponse{}, errors.New("data-probe adapter response is invalid")
	}
	return response, nil
}

func restrictedEnvironment(environment []string) []string {
	allowed := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if name == "PATH" || name == "LANG" || name == "SSL_CERT_FILE" || name == "SSL_CERT_DIR" || strings.HasPrefix(name, "LC_") {
			allowed = append(allowed, entry)
		}
	}
	return allowed
}
