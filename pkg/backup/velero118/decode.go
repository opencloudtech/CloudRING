// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package velero118

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
)

type objectEnvelope struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   Metadata        `json:"metadata"`
	Spec       json.RawMessage `json:"spec"`
	Status     json.RawMessage `json:"status"`
	Data       json.RawMessage `json:"data"`
}

type listEnvelope struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		ResourceVersion string `json:"resourceVersion"`
		Continue        string `json:"continue"`
	} `json:"metadata"`
	Items []json.RawMessage `json:"items"`
}

type ListPage struct {
	ResourceVersion string
	Continue        string
	Items           [][]byte
}

func DecodeRestore(data []byte) (Restore, error) {
	var typed struct {
		Spec   RestoreSpec   `json:"spec"`
		Status RestoreStatus `json:"status"`
	}
	identity, err := decodeObject(data, "velero.io/v1", "Restore", &typed)
	if err != nil {
		return Restore{}, err
	}
	return Restore{Identity: identity, Spec: typed.Spec, Status: typed.Status}, nil
}

type RestoreSpec struct {
	BackupName       string                    `json:"backupName"`
	ScheduleName     string                    `json:"scheduleName"`
	NamespaceMapping map[string]string         `json:"namespaceMapping"`
	UploaderConfig   *UploaderConfigForRestore `json:"uploaderConfig"`
}

type UploaderConfigForRestore struct {
	WriteSparseFiles      *bool `json:"writeSparseFiles"`
	ParallelFilesDownload int   `json:"parallelFilesDownload"`
}
type RestoreStatus struct {
	Phase               string `json:"phase"`
	StartTimestamp      string `json:"startTimestamp"`
	CompletionTimestamp string `json:"completionTimestamp"`
	Errors              int    `json:"errors"`
	Warnings            int    `json:"warnings"`
}

func DecodeBackup(data []byte) (Backup, error) {
	var typed struct {
		Spec   BackupSpec   `json:"spec"`
		Status BackupStatus `json:"status"`
	}
	identity, err := decodeObject(data, "velero.io/v1", "Backup", &typed)
	if err != nil {
		return Backup{}, err
	}
	return Backup{Identity: identity, Spec: typed.Spec, Status: typed.Status}, nil
}

type BackupSpec struct {
	StorageLocation    string                   `json:"storageLocation"`
	SnapshotMoveData   bool                     `json:"snapshotMoveData"`
	DataMover          string                   `json:"datamover"`
	CSISnapshotTimeout string                   `json:"csiSnapshotTimeout"`
	UploaderConfig     *UploaderConfigForBackup `json:"uploaderConfig"`
}

type UploaderConfigForBackup struct {
	ParallelFilesUpload int `json:"parallelFilesUpload"`
}
type BackupStatus struct {
	Phase               string `json:"phase"`
	CompletionTimestamp string `json:"completionTimestamp"`
	Errors              int    `json:"errors"`
	Warnings            int    `json:"warnings"`
}

func DecodeServerStatusRequest(data []byte) (ServerStatusRequest, error) {
	var typed struct {
		Status ServerStatusRequestStatus `json:"status"`
	}
	identity, err := decodeObject(data, "velero.io/v1", "ServerStatusRequest", &typed)
	if err != nil {
		return ServerStatusRequest{}, err
	}
	return ServerStatusRequest{Identity: identity, Status: typed.Status}, nil
}

func DecodePersistentVolumeClaim(data []byte) (PersistentVolumeClaim, error) {
	var typed struct {
		Spec PersistentVolumeClaimSpec `json:"spec"`
	}
	identity, err := decodeObject(data, "v1", "PersistentVolumeClaim", &typed)
	if err != nil {
		return PersistentVolumeClaim{}, err
	}
	return PersistentVolumeClaim{Identity: identity, Spec: typed.Spec}, nil
}

func DecodePersistentVolume(data []byte) (PersistentVolume, error) {
	var typed struct {
		Spec PersistentVolumeSpec `json:"spec"`
	}
	identity, err := decodeObject(data, "v1", "PersistentVolume", &typed)
	if err != nil {
		return PersistentVolume{}, err
	}
	return PersistentVolume{Identity: identity, Spec: typed.Spec}, nil
}

func DecodeDataUpload(data []byte) (DataUpload, error) {
	var typed struct {
		Spec   DataUploadSpec   `json:"spec"`
		Status DataUploadStatus `json:"status"`
	}
	identity, err := decodeObject(data, "velero.io/v2alpha1", "DataUpload", &typed)
	if err != nil {
		return DataUpload{}, err
	}
	return DataUpload{Identity: identity, Spec: typed.Spec, Status: typed.Status}, nil
}

type DataUploadSpec struct {
	SnapshotType          string            `json:"snapshotType"`
	CSISnapshot           *CSISnapshot      `json:"csiSnapshot"`
	SourcePVC             string            `json:"sourcePVC"`
	DataMover             string            `json:"datamover"`
	BackupStorageLocation string            `json:"backupStorageLocation"`
	SourceNamespace       string            `json:"sourceNamespace"`
	DataMoverConfig       map[string]string `json:"dataMoverConfig"`
	Cancel                bool              `json:"cancel"`
	OperationTimeout      string            `json:"operationTimeout"`
}
type DataUploadStatus struct {
	Phase               string            `json:"phase"`
	Message             string            `json:"message"`
	SnapshotID          string            `json:"snapshotID"`
	DataMoverResult     map[string]string `json:"dataMoverResult"`
	StartTimestamp      string            `json:"startTimestamp"`
	CompletionTimestamp string            `json:"completionTimestamp"`
	Progress            Progress          `json:"progress"`
	NodeOS              string            `json:"nodeOS"`
}

func DecodeDataDownload(data []byte) (DataDownload, error) {
	var typed struct {
		Spec   DataDownloadSpec   `json:"spec"`
		Status DataDownloadStatus `json:"status"`
	}
	identity, err := decodeObject(data, "velero.io/v2alpha1", "DataDownload", &typed)
	if err != nil {
		return DataDownload{}, err
	}
	return DataDownload{Identity: identity, Spec: typed.Spec, Status: typed.Status}, nil
}

type DataDownloadSpec struct {
	TargetVolume          TargetVolume      `json:"targetVolume"`
	BackupStorageLocation string            `json:"backupStorageLocation"`
	DataMover             string            `json:"datamover"`
	SnapshotID            string            `json:"snapshotID"`
	SourceNamespace       string            `json:"sourceNamespace"`
	DataMoverConfig       map[string]string `json:"dataMoverConfig"`
	Cancel                bool              `json:"cancel"`
	OperationTimeout      string            `json:"operationTimeout"`
	NodeOS                string            `json:"nodeOS"`
	SnapshotSize          int64             `json:"snapshotSize"`
}
type DataDownloadStatus struct {
	Phase               string   `json:"phase"`
	StartTimestamp      string   `json:"startTimestamp"`
	CompletionTimestamp string   `json:"completionTimestamp"`
	Progress            Progress `json:"progress"`
}

func DecodeConfigMap(data []byte) (ConfigMap, error) {
	var typed struct {
		Data map[string]string `json:"data"`
	}
	identity, err := decodeObject(data, "v1", "ConfigMap", &typed)
	if err != nil {
		return ConfigMap{}, err
	}
	return ConfigMap{Identity: identity, Data: typed.Data}, nil
}

func DecodeDataUploadResult(data []byte) (DataUploadResult, error) {
	var result DataUploadResult
	if err := strictjson.Decode(data, &result); err != nil {
		return DataUploadResult{}, errors.New("decode Velero DataUploadResult")
	}
	return result, nil
}

func DecodeListPage(data []byte, apiVersion, kind string) (ListPage, error) {
	var list listEnvelope
	if err := strictjson.Decode(data, &list); err != nil || list.APIVersion != apiVersion || list.Kind != kind || list.Metadata.ResourceVersion == "" {
		return ListPage{}, errors.New("decode Kubernetes list page")
	}
	page := ListPage{ResourceVersion: list.Metadata.ResourceVersion, Continue: list.Metadata.Continue, Items: make([][]byte, 0, len(list.Items))}
	identities := make([]string, 0, len(list.Items))
	for _, raw := range list.Items {
		var envelope objectEnvelope
		if err := strictjson.Decode(raw, &envelope); err != nil || envelope.APIVersion == "" || envelope.Kind == "" || envelope.Metadata.Name == "" {
			return ListPage{}, errors.New("decode Kubernetes list item")
		}
		identity := envelope.Metadata.Namespace + "\x00" + envelope.Metadata.Name
		identities = append(identities, identity)
		page.Items = append(page.Items, append([]byte(nil), raw...))
	}
	if !sort.StringsAreSorted(identities) {
		return ListPage{}, errors.New("Kubernetes list page is not canonically ordered")
	}
	for index := 1; index < len(identities); index++ {
		if identities[index] == identities[index-1] {
			return ListPage{}, errors.New("Kubernetes list page contains duplicate identity")
		}
	}
	return page, nil
}

func decodeObject(data []byte, apiVersion, kind string, typed any) (Identity, error) {
	var envelope objectEnvelope
	if err := strictjson.Decode(data, &envelope); err != nil || envelope.APIVersion != apiVersion || envelope.Kind != kind {
		return Identity{}, errors.New("decode Kubernetes object")
	}
	metadata := envelope.Metadata
	if metadata.Name == "" || metadata.UID == "" || metadata.ResourceVersion == "" || metadata.DeletionTimestamp != nil && strings.TrimSpace(*metadata.DeletionTimestamp) != "" {
		return Identity{}, errors.New("Kubernetes object identity is invalid")
	}
	var raw map[string]any
	if err := strictjson.Decode(data, &raw); err != nil {
		return Identity{}, errors.New("decode Kubernetes object state")
	}
	stateSHA256, err := restoreproof.CanonicalKubernetesStateSHA256(raw)
	if err != nil {
		return Identity{}, err
	}
	proofStateSHA256, err := proofRelevantKubernetesStateSHA256(raw, kind)
	if err != nil {
		return Identity{}, err
	}
	if err := strictjson.Decode(data, typed); err != nil {
		return Identity{}, errors.New("decode typed Kubernetes object")
	}
	return Identity{Metadata: metadata, StateSHA256: stateSHA256, ProofStateSHA256: proofStateSHA256, Raw: raw}, nil
}

// proofRelevantKubernetesStateSHA256 excludes Kubernetes transport and
// controller bookkeeping while retaining the exact identity, deletion fence,
// desired state, and terminal fields used by the restore proof. Unknown spec
// fields remain covered, so a material storage or lineage change still fails
// closed.
func proofRelevantKubernetesStateSHA256(raw map[string]any, kind string) (string, error) {
	metadata, ok := raw["metadata"].(map[string]any)
	if !ok {
		return "", errors.New("Kubernetes proof state lacks metadata")
	}
	proofMetadata := map[string]any{}
	for _, key := range []string{"name", "namespace", "uid", "deletionTimestamp"} {
		if value, exists := metadata[key]; exists {
			proofMetadata[key] = value
		}
	}
	if kind == "DataDownload" {
		copyProofFields(proofMetadata, metadata, "ownerReferences")
		if labels, ok := metadata["labels"].(map[string]any); ok {
			proofLabels := map[string]any{}
			copyProofFields(proofLabels, labels, "velero.io/restore-name", "velero.io/restore-uid", "velero.io/async-operation-id")
			proofMetadata["labels"] = proofLabels
		}
	}
	projection := map[string]any{
		"apiVersion": raw["apiVersion"],
		"kind":       raw["kind"],
		"metadata":   proofMetadata,
	}
	if spec, exists := raw["spec"]; exists {
		projection["spec"] = spec
	}
	if data, exists := raw["data"]; exists {
		projection["data"] = data
	}
	status, _ := raw["status"].(map[string]any)
	proofStatus := map[string]any{}
	switch kind {
	case "PersistentVolumeClaim", "PersistentVolume":
		copyProofFields(proofStatus, status, "phase")
	case "DataDownload":
		copyProofFields(proofStatus, status, "phase", "startTimestamp", "completionTimestamp", "progress")
	default:
		return restoreproof.CanonicalKubernetesStateSHA256(raw)
	}
	if len(proofStatus) != 0 {
		projection["status"] = proofStatus
	}
	return restoreproof.CanonicalKubernetesStateSHA256(projection)
}

func copyProofFields(destination, source map[string]any, fields ...string) {
	for _, field := range fields {
		if value, exists := source[field]; exists {
			destination[field] = value
		}
	}
}
