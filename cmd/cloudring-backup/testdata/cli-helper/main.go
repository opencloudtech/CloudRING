// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

// Command cli-helper is test-only process plumbing for the cloudring-backup
// CLI end-to-end test. It is intentionally outside production packages.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
	"github.com/opencloudtech/CloudRING/pkg/backup/velero118"
)

const (
	stateEnvironment   = "CLOUDRING_BACKUP_TEST_STATE"
	cleanupEnvironment = "CLOUDRING_BACKUP_TEST_CLEANUP"
)

type helperState struct {
	Objects map[string]json.RawMessage `json:"objects"`
	Lists   map[string]json.RawMessage `json:"lists"`
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "kubectl":
		err = runKubectl(os.Args[2:])
	case "probe", "provider":
		err = runAdapter(os.Args[1])
	default:
		err = errors.New("unknown helper mode")
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "cloudring-backup test helper failed")
		os.Exit(2)
	}
}

func runKubectl(arguments []string) error {
	if len(arguments) != 3 || arguments[0] != "get" || arguments[1] != "--raw" {
		return errors.New("invalid kubectl helper arguments")
	}
	parsed, err := url.Parse(arguments[2])
	if err != nil {
		return err
	}
	state, err := readState()
	if err != nil {
		return err
	}
	cleanup := fileExists(os.Getenv(cleanupEnvironment))
	if parsed.Path == "/api/v1/namespaces/velero/configmaps/backup-volume-1-result" {
		_, _ = io.WriteString(os.Stdout, `{"apiVersion":"v1","kind":"Status","reason":"NotFound","code":404}`)
		return errors.New("synthetic Velero auto-cleaned result")
	}
	if parsed.Path == "/api/v1/namespaces/velero/configmaps" && parsed.Query().Get("fieldSelector") != "" {
		return json.NewEncoder(os.Stdout).Encode(listObject("v1", "ConfigMapList", "auto-cleaned", nil))
	}
	if cleanup && cleanupResource(parsed.Path) {
		if parsed.Query().Get("fieldSelector") != "" {
			apiVersion, kind := cleanupListGVK(parsed.Path)
			return json.NewEncoder(os.Stdout).Encode(listObject(apiVersion, kind, "cleanup", nil))
		}
		_, _ = io.WriteString(os.Stdout, `{"apiVersion":"v1","kind":"Status","reason":"NotFound","code":404}`)
		return errors.New("synthetic not found")
	}
	if parsed.RawQuery == "" {
		if object, ok := state.Objects[parsed.Path]; ok {
			_, err = os.Stdout.Write(object)
			return err
		}
	}
	if list, ok := state.Lists[parsed.Path]; ok {
		_, err = os.Stdout.Write(list)
		return err
	}
	return errors.New("unknown Kubernetes raw path")
}

func runAdapter(mode string) error {
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 128<<10))
	if err != nil || len(input) == 0 {
		return errors.New("read adapter request")
	}
	switch mode {
	case "probe":
		var request velero118.ProbeRequest
		if err := json.Unmarshal(input, &request); err != nil {
			return err
		}
		requestSHA256 := velero118.AdapterRequestSHA256(request)
		started := time.Now().UTC().Truncate(time.Millisecond)
		completed := started.Add(time.Millisecond)
		if wait := time.Until(completed); wait > 0 {
			time.Sleep(wait)
		}
		return json.NewEncoder(os.Stdout).Encode(velero118.ProbeObservation{
			SchemaVersion: velero118.AdapterResponseSchemaVersion, Implementation: "cloudring-volume-probe", Version: "v1",
			RequestSHA256: requestSHA256, AdapterExecutableSHA256: request.AdapterExecutableSHA256, HashAlgorithm: "sha256",
			SourceSHA256: restoreproof.SHA256("tenant-data"), TargetSHA256: restoreproof.SHA256("tenant-data"), ValidatedBytes: 4096,
			StartedAt: started.Format(time.RFC3339Nano), CompletedAt: completed.Format(time.RFC3339Nano),
			EvidenceRef: "runtime/task22a-cli/data-probe", EvidenceSHA256: restoreproof.SHA256("probe-evidence"),
		})
	case "provider":
		var request velero118.BackendRequest
		if err := json.Unmarshal(input, &request); err != nil {
			return err
		}
		requestSHA256 := velero118.AdapterRequestSHA256(request)
		present := request.ArtifactHandleSHA256 == restoreproof.SHA256("source-provider-volume-handle") || !fileExists(os.Getenv(cleanupEnvironment))
		return json.NewEncoder(os.Stdout).Encode(velero118.BackendObservation{
			SchemaVersion: velero118.AdapterResponseSchemaVersion, Implementation: "openstack-cinder", Version: "v1", Present: &present,
			RequestSHA256: requestSHA256, AdapterExecutableSHA256: request.AdapterExecutableSHA256, ArtifactHandleSHA256: request.ArtifactHandleSHA256,
			ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), EvidenceRef: "runtime/task22a-cli/provider", EvidenceSHA256: restoreproof.SHA256("provider-evidence"),
		})
	default:
		return errors.New("invalid adapter mode")
	}
}

func readState() (helperState, error) {
	// #nosec G304 G703 -- only the parent test process supplies this private fixture path.
	payload, err := os.ReadFile(os.Getenv(stateEnvironment))
	if err != nil {
		return helperState{}, err
	}
	var state helperState
	if err := json.Unmarshal(payload, &state); err != nil {
		return helperState{}, err
	}
	return state, nil
}

func cleanupResource(path string) bool {
	switch path {
	case "/api/v1/namespaces/target/persistentvolumeclaims/volume",
		"/api/v1/namespaces/target/persistentvolumeclaims",
		"/api/v1/persistentvolumes/target-pv",
		"/api/v1/persistentvolumes",
		"/apis/velero.io/v2alpha1/namespaces/velero/datadownloads/restore-copy-volume",
		"/apis/velero.io/v2alpha1/namespaces/velero/datadownloads",
		"/api/v1/namespaces/velero/configmaps/backup-volume-1-result",
		"/api/v1/namespaces/velero/configmaps":
		return true
	default:
		return false
	}
}

func cleanupListGVK(path string) (string, string) {
	switch path {
	case "/api/v1/namespaces/target/persistentvolumeclaims":
		return "v1", "PersistentVolumeClaimList"
	case "/api/v1/persistentvolumes":
		return "v1", "PersistentVolumeList"
	case "/apis/velero.io/v2alpha1/namespaces/velero/datadownloads":
		return "velero.io/v2alpha1", "DataDownloadList"
	case "/api/v1/namespaces/velero/configmaps":
		return "v1", "ConfigMapList"
	default:
		return "", ""
	}
}

func listObject(apiVersion, kind, resourceVersion string, items []json.RawMessage) json.RawMessage {
	payload, err := json.Marshal(map[string]any{
		"apiVersion": apiVersion, "kind": kind,
		"metadata": map[string]any{"resourceVersion": resourceVersion, "continue": ""}, "items": items,
	})
	if err != nil {
		panic(err)
	}
	return payload
}

func fileExists(path string) bool {
	// #nosec G703 -- the test parent supplies paths inside its private temporary directory.
	_, err := os.Stat(path)
	return err == nil
}
