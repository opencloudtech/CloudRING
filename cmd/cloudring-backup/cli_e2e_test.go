//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
	"github.com/opencloudtech/CloudRING/pkg/backup/velero118"
)

func TestCollectAndVerifyCLIWithCleanupBarrier(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "cluster-state.json")
	simulatedCleanupPath := filepath.Join(directory, "simulated-cleanup")
	helperBinary := buildCLIHelper(t, directory)
	kubectl := writeCLIHelperExecutable(t, directory, "kubectl", "kubectl", helperBinary, statePath, simulatedCleanupPath)
	probe := writeCLIHelperExecutable(t, directory, "probe", "probe", helperBinary, statePath, simulatedCleanupPath)
	provider := writeCLIHelperExecutable(t, directory, "provider", "provider", helperBinary, statePath, simulatedCleanupPath)

	sourcePVC := cliKubeObject("v1", "PersistentVolumeClaim", cliMetadata("volume", "source", "source-pvc-uid", "10", nil, nil),
		map[string]any{"volumeName": "source-pv", "storageClassName": "fast"}, map[string]any{"phase": "Bound"}, nil)
	writeCLIState(t, statePath, cliHelperState{Objects: map[string]json.RawMessage{
		"/api/v1/namespaces/source/persistentvolumeclaims/volume": sourcePVC,
	}})

	baselineRequestPath := filepath.Join(directory, "baseline-request.json")
	baselinePath := filepath.Join(directory, "source-baseline.json")
	baselineRequest := velero118.BaselineRequest{
		SchemaVersion:   velero118.BaselineRequestSchemaVersion,
		SourceNamespace: "source", SourcePVC: "volume", EvidencePrefix: "runtime/task22a-cli",
	}
	writeJSON(t, baselineRequestPath, baselineRequest, 0o600)
	var baselineOutput bytes.Buffer
	if err := run(t.Context(), []string{"baseline", "--request", baselineRequestPath, "--output", baselinePath, "--kubectl", kubectl}, &baselineOutput); err != nil {
		t.Fatalf("baseline CLI error = %v", err)
	}
	if strings.TrimSpace(baselineOutput.String()) != "status=baseline_written" {
		t.Fatalf("baseline stdout = %q", baselineOutput.String())
	}
	var baseline restoreproof.SourceBaseline
	if err := readStrictJSON(baselinePath, &baseline); err != nil {
		t.Fatal(err)
	}
	baselineAt, err := time.Parse(time.RFC3339Nano, baseline.CapturedAt)
	if err != nil {
		t.Fatal(err)
	}

	request, state, archivedUpload, resultObservation := cliCollectionFixture(t, baselineAt, sourcePVC)
	writeCLIState(t, statePath, state)
	requestPath := filepath.Join(directory, "collection-request.json")
	resultObservationPath := filepath.Join(directory, "data-upload-result-observation.json")
	archivePath := filepath.Join(directory, "backup-contents.tar.gz")
	cleanupReadyPath := filepath.Join(directory, "cleanup-ready.json")
	receiptPath := filepath.Join(directory, "receipt.json")
	writeJSON(t, requestPath, request, 0o600)
	writeJSON(t, resultObservationPath, resultObservation, 0o600)
	writeCLIArchive(t, archivePath, archivedUpload)

	readyResult := make(chan error, 1)
	go func() {
		readyResult <- simulateDownstreamCleanup(t.Context(), cleanupReadyPath, simulatedCleanupPath, request.CleanupRunNonceSHA256)
	}()

	var collectOutput bytes.Buffer
	arguments := []string{
		"collect", "--request", requestPath, "--baseline", baselinePath, "--archive", archivePath,
		"--data-upload-result-observation", resultObservationPath,
		"--data-probe-adapter", probe, "--provider-adapter", provider,
		"--cleanup-ready", cleanupReadyPath, "--cleanup-timeout", "45s", "--poll-interval", "10ms", "--output", receiptPath, "--kubectl", kubectl,
	}
	if err := run(t.Context(), arguments, &collectOutput); err != nil {
		t.Fatalf("collect CLI error = %v", err)
	}
	if strings.TrimSpace(collectOutput.String()) != "status=receipt_written" {
		t.Fatalf("collect stdout = %q", collectOutput.String())
	}
	select {
	case err := <-readyResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("downstream cleanup simulator did not finish")
	}

	var verifyOutput bytes.Buffer
	if err := run(t.Context(), []string{"verify", "--receipt", receiptPath}, &verifyOutput); err != nil {
		t.Fatalf("verify CLI error = %v", err)
	}
	if strings.TrimSpace(verifyOutput.String()) != "status=verified" {
		t.Fatalf("verify stdout = %q", verifyOutput.String())
	}
	for _, path := range []string{cleanupReadyPath, receiptPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("private artifact %s mode = %o", filepath.Base(path), info.Mode().Perm())
		}
	}
	// #nosec G304 -- cleanupReadyPath is a test-owned artifact inside t.TempDir().
	readyBytes, err := os.ReadFile(cleanupReadyPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"source-pvc-uid", "target-pvc-uid", "provider-volume-handle", "restore-copy", "volume"} {
		if bytes.Contains(readyBytes, []byte(forbidden)) {
			t.Fatalf("cleanup marker exposed %q", forbidden)
		}
	}
}

func TestSimulateDownstreamCleanupRejectsMalformedMarker(t *testing.T) {
	directory := t.TempDir()
	readyPath := filepath.Join(directory, "cleanup-ready.json")
	cleanupPath := filepath.Join(directory, "simulated-cleanup")
	if err := os.WriteFile(readyPath, []byte(`{"schemaVersion":`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := simulateDownstreamCleanup(t.Context(), readyPath, cleanupPath, strings.Repeat("b", 64))
	if err == nil || err.Error() != "cleanup-ready marker is malformed" {
		t.Fatalf("simulateDownstreamCleanup() error = %v", err)
	}
}

type cliHelperState struct {
	Objects map[string]json.RawMessage `json:"objects"`
	Lists   map[string]json.RawMessage `json:"lists"`
}

func simulateDownstreamCleanup(ctx context.Context, readyPath, cleanupPath, nonceSHA256 string) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var notice velero118.CleanupReady
		if err := readStrictJSON(readyPath, &notice); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return errors.New("cleanup-ready marker is malformed")
			}
		} else {
			if notice.SchemaVersion != velero118.CleanupReadySchemaVersion || notice.Status != velero118.CleanupReadyStatus || notice.CleanupRunNonceSHA256 != nonceSHA256 {
				return errors.New("cleanup-ready marker is not bound to this run")
			}
			if info, err := os.Stat(readyPath); err != nil || info.Mode().Perm() != 0o600 {
				return errors.New("cleanup-ready marker is not private")
			}
			if err := os.WriteFile(cleanupPath, []byte("ready"), 0o600); err != nil {
				return errors.New("simulate downstream cleanup")
			}
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func cliCollectionFixture(t *testing.T, baselineAt time.Time, sourcePVC []byte) (velero118.CollectionRequest, cliHelperState, []byte, velero118.DataUploadResultObservation) {
	t.Helper()
	trueValue := true
	restoreUID := "restore-uid"
	backupUID := "backup-uid"
	targetUID := "target-pvc-uid"
	timestamp := func(offset time.Duration) string { return baselineAt.Add(offset).UTC().Format(time.RFC3339Nano) }
	backup := cliKubeObject("velero.io/v1", "Backup", cliMetadata("backup-direct", "velero", backupUID, "2", nil, nil), map[string]any{
		"storageLocation": "offcell", "snapshotMoveData": true, "datamover": "", "csiSnapshotTimeout": "10m",
	}, map[string]any{"phase": "Completed", "completionTimestamp": timestamp(-time.Minute), "errors": 0, "warnings": 0}, nil)
	restoreMetadata := cliMetadata("restore-copy", "velero", restoreUID, "3", nil, nil)
	restoreMetadata["creationTimestamp"] = timestamp(500 * time.Microsecond)
	restore := cliKubeObject("velero.io/v1", "Restore", restoreMetadata, map[string]any{
		"backupName": "backup-direct", "scheduleName": "", "namespaceMapping": map[string]string{"source": "target"},
	}, map[string]any{"phase": "Completed", "startTimestamp": timestamp(time.Millisecond), "completionTimestamp": timestamp(4 * time.Millisecond), "errors": 0, "warnings": 0}, nil)
	serverStatus := cliKubeObject("velero.io/v1", "ServerStatusRequest", cliMetadata("cloudring-status", "velero", "server-status-uid", "4", nil, nil), map[string]any{}, map[string]any{
		"phase": "Processed", "processedTimestamp": timestamp(5 * time.Millisecond), "serverVersion": "v1.18.2",
	}, nil)
	targetPVC := cliKubeObject("v1", "PersistentVolumeClaim", cliMetadata("volume", "target", targetUID, "20", nil, nil),
		map[string]any{"volumeName": "target-pv", "storageClassName": "fast"}, map[string]any{"phase": "Bound"}, nil)
	targetPV := cliKubeObject("v1", "PersistentVolume", cliMetadata("target-pv", "", "target-pv-uid", "21", nil, nil), map[string]any{
		"claimRef": map[string]any{"namespace": "target", "name": "volume", "uid": targetUID},
		"csi":      map[string]any{"driver": "cinder.csi.openstack.org", "volumeHandle": "provider-volume-handle"},
	}, map[string]any{"phase": "Bound"}, nil)
	sourcePV := cliKubeObject("v1", "PersistentVolume", cliMetadata("source-pv", "", "source-pv-uid", "11", nil, nil), map[string]any{
		"claimRef": map[string]any{"namespace": "source", "name": "volume", "uid": "source-pvc-uid"},
		"csi":      map[string]any{"driver": "cinder.csi.openstack.org", "volumeHandle": "source-provider-volume-handle"},
	}, map[string]any{"phase": "Bound"}, nil)
	uploadLabels := map[string]string{
		"velero.io/backup-name": "backup-direct", "velero.io/backup-uid": backupUID,
		"velero.io/pvc-uid": "source-pvc-uid", "velero.io/async-operation-id": "du-operation",
	}
	uploadOwners := []map[string]any{{"apiVersion": "velero.io/v1", "kind": "Backup", "name": "backup-direct", "uid": backupUID, "controller": trueValue}}
	dataUpload := cliKubeObject("velero.io/v2alpha1", "DataUpload", cliMetadata("backup-volume-1", "velero", "data-upload-uid", "5", uploadLabels, uploadOwners), map[string]any{
		"snapshotType": "CSI", "csiSnapshot": map[string]any{"volumeSnapshot": "snapshot", "storageClass": "fast", "snapshotClass": "cinder", "driver": "cinder.csi.openstack.org"},
		"sourcePVC": "volume", "datamover": "", "backupStorageLocation": "offcell", "sourceNamespace": "source", "dataMoverConfig": map[string]string{}, "cancel": false, "operationTimeout": "10m",
	}, map[string]any{
		"phase": "Completed", "message": "", "snapshotID": "snapshot-id", "dataMoverResult": map[string]string{}, "startTimestamp": timestamp(-3 * time.Minute),
		"completionTimestamp": timestamp(-2 * time.Minute), "progress": map[string]any{"bytesDone": 4096, "totalBytes": 4096}, "nodeOS": "linux",
	}, nil)
	resultPayload, err := json.Marshal(map[string]any{"backupStorageLocation": "offcell", "datamover": "", "snapshotID": "snapshot-id", "sourceNamespace": "source", "dataMoverResult": map[string]string{}, "nodeOS": "linux", "snapshotSize": 4096})
	if err != nil {
		t.Fatal(err)
	}
	resultMetadata := cliMetadata("backup-volume-1-result", "velero", "result-cm-uid", "6", map[string]string{
		"velero.io/restore-uid": restoreUID, "velero.io/pvc-namespace-name": "source.volume", "velero.io/resource-usage": "DataUpload",
	}, nil)
	resultMetadata["creationTimestamp"] = timestamp(2 * time.Millisecond)
	resultCM := cliKubeObject("v1", "ConfigMap", resultMetadata, nil, nil, map[string]string{restoreUID: string(resultPayload)})
	downloadLabels := map[string]string{
		"velero.io/restore-name": "restore-copy", "velero.io/restore-uid": restoreUID, "velero.io/async-operation-id": "dd-operation",
	}
	downloadOwners := []map[string]any{{"apiVersion": "velero.io/v1", "kind": "Restore", "name": "restore-copy", "uid": restoreUID, "controller": trueValue}}
	dataDownload := cliKubeObject("velero.io/v2alpha1", "DataDownload", cliMetadata("restore-copy-volume", "velero", "data-download-uid", "7", downloadLabels, downloadOwners), map[string]any{
		"targetVolume": map[string]any{"pvc": "volume", "pv": "", "namespace": "target"}, "backupStorageLocation": "offcell", "datamover": "", "snapshotID": "snapshot-id",
		"sourceNamespace": "source", "dataMoverConfig": map[string]string{}, "cancel": false, "operationTimeout": "10m", "nodeOS": "linux", "snapshotSize": 4096,
	}, map[string]any{"phase": "Completed", "startTimestamp": timestamp(2 * time.Millisecond), "completionTimestamp": timestamp(3 * time.Millisecond), "progress": map[string]any{"bytesDone": 4096, "totalBytes": 4096}}, nil)

	state := cliHelperState{
		Objects: map[string]json.RawMessage{
			"/apis/velero.io/v1/namespaces/velero/restores/restore-copy":                   restore,
			"/apis/velero.io/v1/namespaces/velero/backups/backup-direct":                   backup,
			"/apis/velero.io/v1/namespaces/velero/serverstatusrequests/cloudring-status":   serverStatus,
			"/api/v1/namespaces/source/persistentvolumeclaims/volume":                      sourcePVC,
			"/api/v1/persistentvolumes/source-pv":                                          sourcePV,
			"/api/v1/namespaces/target/persistentvolumeclaims/volume":                      targetPVC,
			"/api/v1/persistentvolumes/target-pv":                                          targetPV,
			"/apis/velero.io/v2alpha1/namespaces/velero/datauploads/backup-volume-1":       dataUpload,
			"/apis/velero.io/v2alpha1/namespaces/velero/datadownloads/restore-copy-volume": dataDownload,
		},
		Lists: map[string]json.RawMessage{
			"/apis/velero.io/v2alpha1/namespaces/velero/datauploads":   cliListObject("velero.io/v2alpha1", "DataUploadList", "50", []json.RawMessage{dataUpload}),
			"/apis/velero.io/v2alpha1/namespaces/velero/datadownloads": cliListObject("velero.io/v2alpha1", "DataDownloadList", "51", []json.RawMessage{dataDownload}),
			"/api/v1/namespaces/velero/configmaps":                     cliListObject("v1", "ConfigMapList", "52", nil),
		},
	}
	request := velero118.CollectionRequest{
		SchemaVersion: velero118.CollectionRequestSchemaVersion, VeleroNamespace: "velero", RestoreName: "restore-copy",
		SourceNamespace: "source", SourcePVC: "volume", TargetNamespace: "target", TargetPVC: "volume", DataUploadName: "backup-volume-1",
		ServerStatusRequestName: "cloudring-status", ServerStatusRequestUIDSHA256: restoreproof.SHA256("server-status-uid"),
		CleanupRunNonceSHA256: restoreproof.SHA256("cli-e2e-cleanup-run-nonce"), EvidencePrefix: "runtime/task22a-cli",
	}
	observationRequest := velero118.DataUploadResultObservationRequest{
		SchemaVersion:   velero118.DataUploadResultObservationRequestSchemaVersion,
		VeleroNamespace: request.VeleroNamespace, RestoreName: request.RestoreName, SourceNamespace: request.SourceNamespace,
		SourcePVC: request.SourcePVC, DataUploadName: request.DataUploadName, EvidencePrefix: request.EvidencePrefix,
	}
	resultObservation := velero118.DataUploadResultObservation{
		SchemaVersion:  velero118.DataUploadResultObservationSchemaVersion,
		WatchStartedAt: timestamp(0), ObservedAt: timestamp(2 * time.Millisecond), CapturedAt: timestamp(3 * time.Millisecond),
		RequestSHA256: cliJSONSHA256(t, observationRequest), EventType: "ADDED", Object: resultCM,
		ObjectSHA256: cliCanonicalJSONSHA256(t, resultCM), EvidenceRef: request.EvidencePrefix + "/velero-data-upload-result-observation",
	}
	resultObservation.EvidenceSHA256 = cliObservationEvidenceSHA256(t, resultObservation)
	if wait := time.Until(baselineAt.Add(6 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	return request, state, dataUpload, resultObservation
}

func cliJSONSHA256(t *testing.T, value any) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return restoreproof.SHA256(string(payload))
}

func cliCanonicalJSONSHA256(t *testing.T, payload []byte) string {
	t.Helper()
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	return cliJSONSHA256(t, value)
}

func cliObservationEvidenceSHA256(t *testing.T, observation velero118.DataUploadResultObservation) string {
	t.Helper()
	observation.EvidenceSHA256 = ""
	return cliJSONSHA256(t, observation)
}

func cliMetadata(name, namespace, uid, resourceVersion string, labels map[string]string, owners []map[string]any) map[string]any {
	if labels == nil {
		labels = map[string]string{}
	}
	if owners == nil {
		owners = []map[string]any{}
	}
	return map[string]any{"name": name, "namespace": namespace, "uid": uid, "resourceVersion": resourceVersion, "labels": labels, "ownerReferences": owners}
}

func cliKubeObject(apiVersion, kind string, metadata, spec, status map[string]any, data map[string]string) json.RawMessage {
	value := map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": metadata}
	if spec != nil {
		value["spec"] = spec
	}
	if status != nil {
		value["status"] = status
	}
	if data != nil {
		value["data"] = data
	}
	payload, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return payload
}

func cliListObject(apiVersion, kind, resourceVersion string, items []json.RawMessage) json.RawMessage {
	payload, err := json.Marshal(map[string]any{
		"apiVersion": apiVersion, "kind": kind,
		"metadata": map[string]any{"resourceVersion": resourceVersion, "continue": ""}, "items": items,
	})
	if err != nil {
		panic(err)
	}
	return payload
}

func writeCLIState(t *testing.T, path string, state cliHelperState) {
	t.Helper()
	writeJSON(t, path, state, 0o600)
}

func writeCLIHelperExecutable(t *testing.T, directory, name, mode, helperBinary, statePath, cleanupPath string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	body := "#!/bin/sh\nCLOUDRING_BACKUP_TEST_STATE=" + strconv.Quote(statePath) +
		" CLOUDRING_BACKUP_TEST_CLEANUP=" + strconv.Quote(cleanupPath) +
		" exec " + strconv.Quote(helperBinary) + " " + mode + " \"$@\"\n"
	// #nosec G306 -- test-only executable in a per-test private directory.
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildCLIHelper(t *testing.T, directory string) string {
	t.Helper()
	path := filepath.Join(directory, "cli-helper")
	// #nosec G204 -- command, package path, and output location are fixed test inputs; no production value reaches the shell.
	command := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-o", path, "./testdata/cli-helper")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build CLI test helper: %v (%d bytes of hidden output)", err, len(output))
	}
	return path
}

func writeCLIArchive(t *testing.T, path string, dataUpload []byte) {
	t.Helper()
	// #nosec G304 -- path is a test-owned artifact inside t.TempDir().
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, name := range []string{
		"resources/datauploads.velero.io/namespaces/velero/backup-volume-1.json",
		"resources/datauploads.velero.io/v2alpha1-preferredversion/namespaces/velero/backup-volume-1.json",
	} {
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(dataUpload)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(dataUpload); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
