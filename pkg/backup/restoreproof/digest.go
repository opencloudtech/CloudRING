// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package restoreproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
)

// SHA256 returns a lowercase digest without retaining the input value.
func SHA256(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// CanonicalKubernetesStateSHA256 hashes the complete decoded object except
// Kubernetes transport metadata that changes without a semantic state change.
// Unknown fields remain in the digest.
func CanonicalKubernetesStateSHA256(object map[string]any) (string, error) {
	encoded, err := json.Marshal(object)
	if err != nil {
		return "", errors.New("encode Kubernetes object state")
	}
	var canonical map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&canonical); err != nil {
		return "", errors.New("copy Kubernetes object state")
	}
	metadata, ok := canonical["metadata"].(map[string]any)
	if !ok {
		return "", errors.New("Kubernetes object state lacks metadata")
	}
	delete(metadata, "resourceVersion")
	delete(metadata, "managedFields")
	delete(metadata, "creationTimestamp")
	delete(metadata, "selfLink")
	encoded, err = json.Marshal(canonical)
	if err != nil {
		return "", errors.New("canonicalize Kubernetes object state")
	}
	return SHA256(string(encoded)), nil
}

type probeDigestItem struct {
	SourceIdentity      string `json:"sourceIdentity"`
	SourceUIDSHA256     string `json:"sourceUidSha256"`
	TargetIdentity      string `json:"targetIdentity"`
	TargetUIDSHA256     string `json:"targetUidSha256"`
	TargetPVIdentity    string `json:"targetPvIdentity"`
	TargetPVUIDSHA256   string `json:"targetPvUidSha256"`
	SourcePVCVolumeName string `json:"sourcePvcVolumeName"`
	RequestSHA256       string `json:"requestSha256"`
	AdapterSHA256       string `json:"adapterExecutableSha256"`
	SourceDataSHA256    string `json:"sourceDataSha256"`
	RestoredDataSHA256  string `json:"restoredDataSha256"`
	ValidatedBytes      int64  `json:"validatedBytes"`
	StartedAt           string `json:"startedAt"`
	CompletedAt         string `json:"completedAt"`
}

func ProbeSetSHA256(probes []DataProbe) string {
	items := make([]probeDigestItem, 0, len(probes))
	for index := range probes {
		probe := &probes[index]
		items = append(items, probeDigestItem{
			SourceIdentity:      sourceIdentity(probe.Source),
			SourceUIDSHA256:     sourceUID(probe.Source),
			TargetIdentity:      targetIdentity(probe.Target),
			TargetUIDSHA256:     targetUID(probe.Target),
			TargetPVIdentity:    targetIdentity(probe.TargetPV),
			TargetPVUIDSHA256:   targetUID(probe.TargetPV),
			SourcePVCVolumeName: probe.SourcePVCVolumeName,
			RequestSHA256:       probe.RequestSHA256,
			AdapterSHA256:       probe.AdapterExecutableSHA256,
			SourceDataSHA256:    probe.SourceDataSHA256,
			RestoredDataSHA256:  probe.RestoredDataSHA256,
			ValidatedBytes:      probe.ValidatedBytes,
			StartedAt:           probe.StartedAt,
			CompletedAt:         probe.CompletedAt,
		})
	}
	sort.Slice(items, func(left, right int) bool { return items[left].SourceIdentity < items[right].SourceIdentity })
	return digest(items)
}

type aggregateDigestItem struct {
	SourceIdentity string `json:"sourceIdentity"`
	DataSHA256     string `json:"dataSha256"`
	ValidatedBytes int64  `json:"validatedBytes"`
}

func AggregateDataSHA256(probes []DataProbe) string {
	items := make([]aggregateDigestItem, 0, len(probes))
	for index := range probes {
		probe := &probes[index]
		items = append(items, aggregateDigestItem{
			SourceIdentity: sourceIdentity(probe.Source),
			DataSHA256:     probe.SourceDataSHA256,
			ValidatedBytes: probe.ValidatedBytes,
		})
	}
	sort.Slice(items, func(left, right int) bool { return items[left].SourceIdentity < items[right].SourceIdentity })
	return digest(struct {
		SchemaVersion string                `json:"schemaVersion"`
		Volumes       []aggregateDigestItem `json:"volumes"`
	}{SchemaVersion: "cloudring.restore-data-aggregate/v1", Volumes: items})
}

func BackendLineageSHA256(method string, backend *BackendArtifactLineage) string {
	if backend == nil {
		return ""
	}
	return digest(struct {
		Method                     string          `json:"method"`
		ArtifactHandleSHA256       string          `json:"artifactHandleSha256"`
		SourceArtifactHandleSHA256 string          `json:"sourceArtifactHandleSha256"`
		SourceKind                 string          `json:"sourceKind"`
		DerivedFrom                *TargetResource `json:"derivedFrom"`
		TargetPVC                  *TargetResource `json:"targetPvc"`
		TargetPV                   *TargetResource `json:"targetPv"`
		SourcePV                   *SourceResource `json:"sourcePv"`
	}{method, backend.ArtifactHandleSHA256, backend.SourceArtifactHandleSHA256, backend.SourceKind, backend.DerivedFrom, backend.TargetPVC, backend.TargetPV, backend.SourcePV})
}

func ProviderAbsenceQuerySHA256(backend *BackendArtifactLineage) string {
	if backend == nil {
		return ""
	}
	return digest(struct {
		SchemaVersion          string `json:"schemaVersion"`
		ProviderImplementation string `json:"providerImplementation"`
		ProviderVersion        string `json:"providerVersion"`
		SourceKind             string `json:"sourceKind"`
		ArtifactHandleSHA256   string `json:"artifactHandleSha256"`
	}{"cloudring.provider-absence-query/v1", backend.ProviderImplementation, backend.ProviderVersion, backend.SourceKind, backend.ArtifactHandleSHA256})
}

func ProviderSourceContinuityQuerySHA256(backend *BackendArtifactLineage) string {
	if backend == nil {
		return ""
	}
	return digest(struct {
		SchemaVersion          string `json:"schemaVersion"`
		ProviderImplementation string `json:"providerImplementation"`
		ProviderVersion        string `json:"providerVersion"`
		SourceKind             string `json:"sourceKind"`
		ArtifactHandleSHA256   string `json:"artifactHandleSha256"`
	}{"cloudring.provider-source-continuity-query/v1", backend.ProviderImplementation, backend.ProviderVersion, backend.SourceKind, backend.SourceArtifactHandleSHA256})
}

func ProviderObservationSHA256(querySHA256, requestSHA256, adapterSHA256, status, observedAt string) string {
	return digest(struct {
		SchemaVersion           string `json:"schemaVersion"`
		QuerySHA256             string `json:"querySha256"`
		RequestSHA256           string `json:"requestSha256"`
		AdapterExecutableSHA256 string `json:"adapterExecutableSha256"`
		Status                  string `json:"status"`
		ObservedAt              string `json:"observedAt"`
	}{"cloudring.provider-observation/v1", querySHA256, requestSHA256, adapterSHA256, status, observedAt})
}

// BackendEvidenceSHA256 binds the provider-present and final absence evidence
// without retaining a raw provider handle.
func BackendEvidenceSHA256(backend *BackendArtifactLineage) string {
	if backend == nil || backend.PresenceObservation == nil || backend.SourcePresenceObservation == nil {
		return ""
	}
	absence := make([]string, 0, len(backend.AbsenceObservations))
	for _, observation := range backend.AbsenceObservations {
		absence = append(absence, observation.ObservationSHA256)
	}
	return digest(struct {
		Presence       string   `json:"presence"`
		Absence        []string `json:"absence"`
		SourcePresence string   `json:"sourcePresence"`
	}{backend.PresenceObservation.ObservationSHA256, absence, backend.SourcePresenceObservation.ObservationSHA256})
}

// SourceBaselineEvidenceSHA256 is the canonical evidence digest written by
// the baseline command and rechecked by the offline receipt validator.
func SourceBaselineEvidenceSHA256(baseline SourceBaseline) string {
	return digest(struct {
		SchemaVersion string         `json:"schemaVersion"`
		CapturedAt    string         `json:"capturedAt"`
		Source        SourceResource `json:"source"`
	}{baseline.SchemaVersion, baseline.CapturedAt, baseline.Source})
}

// VeleroRuntimeEvidenceSHA256 binds an official ServerStatusRequest object to
// the exact version and processing timestamp carried in the receipt.
func VeleroRuntimeEvidenceSHA256(attestation VeleroRuntimeAttestation) string {
	return digest(struct {
		GVR           GVR             `json:"gvr"`
		Object        *TargetResource `json:"object"`
		ServerVersion string          `json:"serverVersion"`
		Phase         string          `json:"phase"`
		ProcessedAt   string          `json:"processedAt"`
		ObservedAt    string          `json:"observedAt"`
	}{attestation.GVR, attestation.Object, attestation.ServerVersion, attestation.Phase, attestation.ProcessedAt, attestation.ObservedAt})
}

func ProviderAbsenceSetSHA256(backends []BackendArtifactLineage) string {
	type item struct {
		SourceKind             string `json:"sourceKind"`
		DerivedFromIdentity    string `json:"derivedFromIdentity"`
		ArtifactHandleSHA256   string `json:"artifactHandleSha256"`
		FinalObservedAt        string `json:"finalObservedAt"`
		FinalQuerySHA256       string `json:"finalQuerySha256"`
		FinalObservationSHA256 string `json:"finalObservationSha256"`
	}
	items := make([]item, 0, len(backends))
	for index := range backends {
		backend := &backends[index]
		entry := item{SourceKind: backend.SourceKind, DerivedFromIdentity: targetIdentity(backend.DerivedFrom), ArtifactHandleSHA256: backend.ArtifactHandleSHA256}
		if len(backend.AbsenceObservations) != 0 {
			last := backend.AbsenceObservations[len(backend.AbsenceObservations)-1]
			entry.FinalObservedAt = last.ObservedAt
			entry.FinalQuerySHA256 = last.QuerySHA256
			entry.FinalObservationSHA256 = last.ObservationSHA256
		}
		items = append(items, entry)
	}
	sort.Slice(items, func(left, right int) bool {
		return items[left].SourceKind+"\x00"+items[left].DerivedFromIdentity < items[right].SourceKind+"\x00"+items[right].DerivedFromIdentity
	})
	return digest(items)
}

func DataLineageEvidenceSHA256(lineage *DataLineage) string {
	if lineage == nil {
		return ""
	}
	return digest(struct {
		ProbeSetSHA256           string `json:"probeSetSha256"`
		AggregateDataSHA256      string `json:"aggregateDataSha256"`
		ProviderAbsenceSetSHA256 string `json:"providerAbsenceSetSha256"`
	}{lineage.ProbeSetSHA256, lineage.AggregateDataSHA256, lineage.ProviderAbsenceSetSHA256})
}

func DataUploadEvidenceSHA256(upload *DataUploadProof) string {
	if upload == nil {
		return ""
	}
	return digest(struct {
		UIDSHA256             string `json:"uidSha256"`
		ArchivedObjectSHA256  string `json:"archivedObjectSha256"`
		ResourceVersionSHA256 string `json:"resourceVersionSha256"`
	}{upload.UIDSHA256, upload.ArchivedObjectSHA256, upload.ResourceVersionSHA256})
}

func DataUploadResultEvidenceSHA256(result *DataUploadResultProof) string {
	if result == nil || result.Object == nil {
		return ""
	}
	return digest(struct {
		ObjectSHA256      string `json:"objectSha256"`
		PayloadSHA256     string `json:"payloadSha256"`
		ObservedAt        string `json:"observedAt"`
		VeleroAutoDeleted string `json:"veleroAutoDeletedAt"`
	}{result.Object.ValidatedStateSHA256, result.ResultPayloadSHA256, result.ObservedAt, result.VeleroAutoDeletedAt})
}

func DataDownloadEvidenceSHA256(helper *AsyncHelper) string {
	if helper == nil || helper.Object == nil {
		return ""
	}
	return digest(struct {
		ObjectSHA256    string `json:"objectSha256"`
		OperationSHA256 string `json:"operationSha256"`
	}{helper.Object.ValidatedStateSHA256, helper.OperationIDSHA256})
}

func ReceiptSHA256(receipt VolumeReceipt) string {
	receipt.ReceiptSHA256 = ""
	return digest(receipt)
}

func digest(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return SHA256(string(payload))
}

func sourceIdentity(resource *SourceResource) string {
	if resource == nil {
		return ""
	}
	return objectIdentity(resource.Resource, resource.Namespace, resource.Name)
}

func targetIdentity(resource *TargetResource) string {
	if resource == nil {
		return ""
	}
	return objectIdentity(resource.Resource, resource.Namespace, resource.Name)
}

func sourceUID(resource *SourceResource) string {
	if resource == nil {
		return ""
	}
	return resource.UIDSHA256
}

func targetUID(resource *TargetResource) string {
	if resource == nil {
		return ""
	}
	return resource.UIDSHA256
}

func objectIdentity(resource, namespace, name string) string {
	return resource + "\x00" + namespace + "\x00" + name
}
