// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package velero118

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
)

var ErrNotFound = errors.New("Kubernetes object not found")

const (
	providerAbsenceMinimumInterval = 10 * time.Second
	providerAbsenceClockSkewMargin = time.Second
	serverStatusMaximumAge         = time.Minute
	serverStatusAllowedFutureSkew  = 30 * time.Second
	sourceBaselineMaximumAge       = 15 * time.Minute
)

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }
func (systemClock) Wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// SystemClock returns the production context-cancellable clock.
func SystemClock() Clock { return systemClock{} }

// BuildSourceBaseline observes the exact source PVC before a restore.
func BuildSourceBaseline(ctx context.Context, reader KubernetesReader, request BaselineRequest, clock Clock) (restoreproof.SourceBaseline, error) {
	if err := validateBaselineRequest(request); err != nil {
		return restoreproof.SourceBaseline{}, err
	}
	if reader == nil {
		return restoreproof.SourceBaseline{}, errors.New("source baseline Kubernetes reader is missing")
	}
	if clock == nil {
		clock = SystemClock()
	}
	reader = withReadRetries(reader, clock)
	payload, err := reader.Get(ctx, restoreproof.CoreV1PVCGVR, request.SourceNamespace, request.SourcePVC)
	if err != nil {
		return restoreproof.SourceBaseline{}, errors.New("read source PVC baseline")
	}
	pvc, err := DecodePersistentVolumeClaim(payload)
	if err != nil || pvc.Identity.Metadata.Namespace != request.SourceNamespace || pvc.Identity.Metadata.Name != request.SourcePVC {
		return restoreproof.SourceBaseline{}, errors.New("source PVC baseline identity is invalid")
	}
	resource := restoreproof.SourceResource{
		Resource:                    "persistentvolumeclaims",
		Namespace:                   request.SourceNamespace,
		Name:                        request.SourcePVC,
		UIDSHA256:                   restoreproof.SHA256(pvc.Identity.Metadata.UID),
		ResourceVersionBeforeSHA256: restoreproof.SHA256(pvc.Identity.Metadata.ResourceVersion),
		ResourceVersionAfterSHA256:  restoreproof.SHA256(pvc.Identity.Metadata.ResourceVersion),
		StateBeforeSHA256:           pvc.Identity.ProofStateSHA256,
		StateAfterSHA256:            pvc.Identity.ProofStateSHA256,
	}
	baseline := restoreproof.SourceBaseline{
		SchemaVersion: restoreproof.BaselineSchemaVersion,
		CapturedAt:    canonicalTimestamp(clock.Now()),
		Source:        resource,
		EvidenceRef:   request.EvidencePrefix + "/source-pvc-baseline",
	}
	baseline.EvidenceSHA256 = restoreproof.SourceBaselineEvidenceSHA256(baseline)
	return baseline, nil
}

// CollectCSIDataMoverVolumeLineage performs real exact-GVR reads, invokes the
// independent data/provider observers, waits for downstream cleanup, and emits
// an unsigned source-safe receipt. It never deletes workloads itself.
func CollectCSIDataMoverVolumeLineage(
	ctx context.Context,
	reader KubernetesReader,
	probeObserver ProbeObserver,
	backendObserver BackendObserver,
	cleanupBarrier CleanupBarrier,
	request CollectionRequest,
	baseline restoreproof.SourceBaseline,
	archivedDataUpload []byte,
	clock Clock,
) (restoreproof.VolumeReceipt, error) {
	if err := validateRequest(request); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	if reader == nil || probeObserver == nil || backendObserver == nil || cleanupBarrier == nil {
		return restoreproof.VolumeReceipt{}, errors.New("restore proof collector dependency is missing")
	}
	if clock == nil {
		clock = SystemClock()
	}
	reader = withReadRetries(reader, clock)
	if err := validateBaseline(request, baseline); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}

	restoreObject, err := readRestore(ctx, reader, request)
	if err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	if err := validateBaselineTimeline(baseline, restoreObject); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	veleroRuntime, err := readVeleroRuntime(ctx, reader, request, restoreObject, clock)
	if err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	backupObject, err := readBackup(ctx, reader, request, restoreObject)
	if err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	sourcePVC, sourcePV, targetPVC, targetPV, sourceProof, err := readPVCLineage(ctx, reader, request, baseline)
	if err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	sourcePVProof := sourceResourceFromIdentity(sourcePV.Identity, "persistentvolumes")
	archivedUpload, err := DecodeDataUpload(archivedDataUpload)
	if err != nil {
		return restoreproof.VolumeReceipt{}, errors.New("decode archived Velero DataUpload")
	}
	liveUpload, err := findDataUpload(ctx, reader, request, backupObject, sourcePVC, archivedUpload)
	if err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	resultConfigMap, resultPayload, result, resultObservedAt, err := readObservedDataUploadResult(request, restoreObject, sourceProof)
	if err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	dataDownload, err := findDataDownload(ctx, reader, request, restoreObject, targetPVC, result)
	if err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	if err := crossValidateDataPath(request, restoreObject, backupObject, sourcePVC, sourcePV, targetPVC, targetPV, liveUpload, archivedUpload, resultConfigMap, result, dataDownload); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	resultAutoDeletedAt, err := confirmVeleroAutoDeletedDataUploadResult(ctx, reader, request, resultConfigMap, restoreObject, clock)
	if err != nil {
		return restoreproof.VolumeReceipt{}, err
	}

	probeRequest := ProbeRequest{
		SchemaVersion:                 AdapterRequestSchemaVersion,
		RequestDigestCanonicalization: AdapterRequestCanonicalization,
		AdapterExecutableSHA256:       probeObserver.IdentitySHA256(),
		Source:                        ObjectQuery{GVR: restoreproof.CoreV1PVCGVR, Namespace: request.SourceNamespace, Name: request.SourcePVC, UIDSHA256: sourceProof.UIDSHA256},
		Target:                        ObjectQuery{GVR: restoreproof.CoreV1PVCGVR, Namespace: request.TargetNamespace, Name: request.TargetPVC, UIDSHA256: restoreproof.SHA256(targetPVC.Identity.Metadata.UID)},
	}
	probeObservation, err := observeProbe(ctx, probeObserver, probeRequest, clock)
	if err != nil {
		return restoreproof.VolumeReceipt{}, errors.New("independent data probe failed")
	}
	if probeObservation.ValidatedBytes != liveUpload.Status.Progress.TotalBytes {
		return restoreproof.VolumeReceipt{}, errors.New("data probe did not validate the complete restored byte stream")
	}

	providerHandleSHA256 := restoreproof.SHA256(targetPV.Spec.CSI.VolumeHandle)
	backend := restoreproof.BackendArtifactLineage{
		Status:                     "deleted-and-absent",
		ArtifactHandleSHA256:       providerHandleSHA256,
		SourceKind:                 "persistent-volume",
		DerivedFrom:                targetPointer(targetPV.Identity.Target("persistentvolumes")),
		TargetPVC:                  targetPointer(targetPVC.Identity.Target("persistentvolumeclaims")),
		TargetPV:                   targetPointer(targetPV.Identity.Target("persistentvolumes")),
		SourcePV:                   sourcePointer(sourcePVProof),
		SourceArtifactHandleSHA256: restoreproof.SHA256(sourcePV.Spec.CSI.VolumeHandle),
		EvidenceRef:                request.EvidencePrefix + "/provider-volume-lineage",
	}
	cleanupTargets := []observedTarget{
		{GVR: restoreproof.CoreV1PVCGVR, Namespace: request.TargetNamespace, Name: request.TargetPVC, Proof: targetPVC.Identity.Target("persistentvolumeclaims")},
		{GVR: restoreproof.CoreV1PVGVR, Name: targetPV.Identity.Metadata.Name, Proof: targetPV.Identity.Target("persistentvolumes")},
		{GVR: restoreproof.DataDownloadGVR, Namespace: request.VeleroNamespace, Name: dataDownload.Identity.Metadata.Name, Proof: dataDownload.Identity.Target("datadownloads.velero.io")},
	}
	autoCleanedTarget := observedTarget{GVR: restoreproof.CoreV1CMGVR, Namespace: request.VeleroNamespace, Name: resultConfigMap.Identity.Metadata.Name, Proof: resultConfigMap.Identity.Target("configmaps")}
	allTargets := append(append([]observedTarget(nil), cleanupTargets...), autoCleanedTarget)
	if err := fenceProofRelevantCleanupTargets(ctx, reader, cleanupTargets); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	if err := requireExactAbsentObservedTarget(ctx, reader, autoCleanedTarget); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	if err := sourceStillUnchanged(ctx, reader, request, baseline, sourcePVProof); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	presentObservation, err := observeBackend(ctx, backendObserver, targetPV.Spec.CSI.VolumeHandle, clock)
	if err != nil || presentObservation.Present == nil || !*presentObservation.Present {
		return restoreproof.VolumeReceipt{}, errors.New("provider artifact was not present before cleanup")
	}
	backend.ProviderImplementation = presentObservation.Implementation
	backend.ProviderVersion = presentObservation.Version
	backend.LineageSHA256 = restoreproof.BackendLineageSHA256(restoreproof.MethodCSIDataMover, &backend)
	querySHA256 := restoreproof.ProviderAbsenceQuerySHA256(&backend)
	backend.PresenceObservation = providerObservationProof(presentObservation, "present", querySHA256)
	if err := fenceProofRelevantCleanupTargets(ctx, reader, cleanupTargets); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	if err := requireExactAbsentObservedTarget(ctx, reader, autoCleanedTarget); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	if err := sourceStillUnchanged(ctx, reader, request, baseline, sourcePVProof); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}

	validationCompletedAt := probeObservation.CompletedAt
	if timestampAfter(validationCompletedAt, resultAutoDeletedAt) {
		validationCompletedAt = resultAutoDeletedAt
	}
	cleanupReady := CleanupReady{
		SchemaVersion:         CleanupReadySchemaVersion,
		Status:                CleanupReadyStatus,
		ReadyAt:               canonicalTimestamp(clock.Now()),
		CleanupRunNonceSHA256: request.CleanupRunNonceSHA256,
	}
	cleanupStartedAt := cleanupReady.ReadyAt
	if err := validatePreCleanupTimeline(restoreObject, probeObservation, presentObservation, cleanupReady); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	if err := cleanupBarrier.ReadyForCleanup(ctx, cleanupReady); err != nil {
		return restoreproof.VolumeReceipt{}, errors.New("publish cleanup readiness barrier")
	}
	cleanupCompletedAt, err := waitForExactCleanup(ctx, reader, cleanupTargets, request, clock)
	if err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	if err := requireExactAbsentObservedTarget(ctx, reader, autoCleanedTarget); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	if err := sourceStillUnchanged(ctx, reader, request, baseline, sourcePVProof); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}

	backend.DeletedAt = cleanupCompletedAt
	firstAbsence, err := observeAbsence(ctx, backendObserver, targetPV.Spec.CSI.VolumeHandle, backend, querySHA256, clock)
	if err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	if timestampTooFarInFuture(firstAbsence.ObservedAt, clock.Now(), 30*time.Second) {
		return restoreproof.VolumeReceipt{}, errors.New("provider absence observation timestamp is invalid")
	}
	backend.AbsenceObservations = append(backend.AbsenceObservations, firstAbsence)
	// Wait on the local monotonic clock beyond the evidence interval because
	// provider observations carry wall-clock timestamps. A small NTP correction
	// must not make an otherwise valid absence proof intermittently fail, while
	// the timestamp validator below still enforces the full minimum interval.
	if err := clock.Wait(ctx, providerAbsenceMinimumInterval+providerAbsenceClockSkewMargin); err != nil {
		return restoreproof.VolumeReceipt{}, errors.New("provider absence interval interrupted")
	}
	if _, err := requireExactCleanup(ctx, reader, cleanupTargets); err != nil {
		return restoreproof.VolumeReceipt{}, errors.New("Kubernetes cleanup quiet fence failed")
	}
	if err := sourceStillUnchanged(ctx, reader, request, baseline, sourcePVProof); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	secondAbsence, err := observeAbsence(ctx, backendObserver, targetPV.Spec.CSI.VolumeHandle, backend, querySHA256, clock)
	if err != nil {
		return restoreproof.VolumeReceipt{}, err
	}
	backend.AbsenceObservations = append(backend.AbsenceObservations, secondAbsence)
	if !timestampAtLeast(firstAbsence.ObservedAt, secondAbsence.ObservedAt, providerAbsenceMinimumInterval) {
		return restoreproof.VolumeReceipt{}, errors.New("provider absence observations are too close")
	}
	if timestampTooFarInFuture(secondAbsence.ObservedAt, clock.Now(), 30*time.Second) {
		return restoreproof.VolumeReceipt{}, errors.New("provider absence observation timestamp is invalid")
	}
	sourcePresenceRaw, err := observeBackend(ctx, backendObserver, sourcePV.Spec.CSI.VolumeHandle, clock)
	if err != nil || sourcePresenceRaw.Present == nil || !*sourcePresenceRaw.Present ||
		sourcePresenceRaw.Implementation != backend.ProviderImplementation || sourcePresenceRaw.Version != backend.ProviderVersion {
		return restoreproof.VolumeReceipt{}, errors.New("source provider artifact continuity observation failed")
	}
	sourceQuerySHA256 := restoreproof.ProviderSourceContinuityQuerySHA256(&backend)
	backend.SourcePresenceObservation = providerObservationProof(sourcePresenceRaw, "present", sourceQuerySHA256)
	if !timestampAfter(secondAbsence.ObservedAt, backend.SourcePresenceObservation.ObservedAt) ||
		timestampTooFarInFuture(backend.SourcePresenceObservation.ObservedAt, clock.Now(), 30*time.Second) {
		return restoreproof.VolumeReceipt{}, errors.New("source provider artifact continuity timestamp is invalid")
	}
	if allAbsent, err := requireExactCleanup(ctx, reader, cleanupTargets); err != nil || !allAbsent {
		return restoreproof.VolumeReceipt{}, errors.New("final Kubernetes cleanup fence failed")
	}
	if err := requireExactAbsentObservedTarget(ctx, reader, autoCleanedTarget); err != nil {
		return restoreproof.VolumeReceipt{}, errors.New("final Velero auto-cleaned resource fence failed")
	}
	if err := sourceStillUnchanged(ctx, reader, request, baseline, sourcePVProof); err != nil {
		return restoreproof.VolumeReceipt{}, err
	}

	retainedUploadBytes, err := reader.Get(ctx, restoreproof.DataUploadGVR, request.VeleroNamespace, liveUpload.Identity.Metadata.Name)
	if err != nil {
		return restoreproof.VolumeReceipt{}, errors.New("retained DataUpload disappeared after restore cleanup")
	}
	retainedUpload, err := DecodeDataUpload(retainedUploadBytes)
	if err != nil || !sameDataUpload(liveUpload, retainedUpload) {
		return restoreproof.VolumeReceipt{}, errors.New("retained DataUpload changed after restore cleanup")
	}
	if observer, ok := cleanupBarrier.(PostCleanupObserver); ok {
		if err := observer.ObservePostCleanup(ctx); err != nil {
			return restoreproof.VolumeReceipt{}, errors.New("observe post-cleanup source continuity")
		}
	}

	verifiedAt := maxCanonicalTimestamp(clock.Now(), backend.SourcePresenceObservation.ObservedAt)
	backend.EvidenceSHA256 = restoreproof.BackendEvidenceSHA256(&backend)
	contextProof := restoreproof.VolumeRestoreContext{
		VeleroNamespace:              request.VeleroNamespace,
		RestoreID:                    restoreObject.Identity.Metadata.Name,
		RestoreUIDSHA256:             restoreproof.SHA256(restoreObject.Identity.Metadata.UID),
		RestoreResourceVersionSHA256: restoreproof.SHA256(restoreObject.Identity.Metadata.ResourceVersion),
		BackupID:                     backupObject.Identity.Metadata.Name,
		BackupUIDSHA256:              restoreproof.SHA256(backupObject.Identity.Metadata.UID),
		BackupResourceVersionSHA256:  restoreproof.SHA256(backupObject.Identity.Metadata.ResourceVersion),
		BackupStorageLocation:        backupObject.Spec.StorageLocation,
		BackupCompletedAt:            backupObject.Status.CompletionTimestamp,
		NamespaceMapping:             cloneStringMap(restoreObject.Spec.NamespaceMapping),
		RestoreStartedAt:             restoreObject.Status.StartTimestamp,
		CompletedAt:                  restoreObject.Status.CompletionTimestamp,
		CSISnapshotTimeout:           backupObject.Spec.CSISnapshotTimeout,
		BackupUploaderConfigSHA256:   optionalMapSHA256(expectedBackupUploaderConfig(backupObject.Spec.UploaderConfig)),
		RestoreUploaderConfigSHA256:  optionalMapSHA256(expectedRestoreUploaderConfig(restoreObject.Spec.UploaderConfig)),
		DataMoverConfigSHA256:        optionalMapSHA256(dataDownload.Spec.DataMoverConfig),
		SourceBaseline:               baseline,
		Cleanup: restoreproof.CleanupContext{
			ValidationCompletedAt:      validationCompletedAt,
			CleanupStartedAt:           cleanupStartedAt,
			CleanupCompletedAt:         cleanupCompletedAt,
			VerifiedAt:                 verifiedAt,
			TargetResources:            targetProofs(allTargets),
			VeleroAutoCleanedResources: []restoreproof.TargetResource{autoCleanedTarget.Proof},
			SourceResources:            []restoreproof.SourceResource{sourceProof, sourcePVProof},
		},
	}
	resultPayloadSHA256 := canonicalJSONSHA256([]byte(resultPayload))
	archivedObjectSHA256 := canonicalJSONSHA256(archivedDataUpload)
	dataUploadProof := buildDataUploadProof(request, backupObject, sourceProof, archivedObjectSHA256, retainedUpload, verifiedAt)
	resultProof := buildDataUploadResultProof(request, restoreObject, sourceProof, resultConfigMap, result, dataUploadProof, resultPayloadSHA256, resultObservedAt, resultAutoDeletedAt)
	probeProof := buildProbeProof(sourceProof, sourcePVC, targetPVC, targetPV, probeObservation)
	helperProof := buildHelperProof(request, restoreObject, sourceProof, targetPVC, targetPV, dataDownload, resultProof, dataUploadProof)
	lineage := restoreproof.DataLineage{
		Status:           "verified",
		Method:           restoreproof.MethodCSIDataMover,
		Probes:           []restoreproof.DataProbe{probeProof},
		ValidatedBytes:   probeProof.ValidatedBytes,
		Helpers:          []restoreproof.AsyncHelper{helperProof},
		BackendArtifacts: []restoreproof.BackendArtifactLineage{backend},
		EvidenceRef:      request.EvidencePrefix + "/csi-data-mover-lineage",
	}
	lineage.ProbeSetSHA256 = restoreproof.ProbeSetSHA256(lineage.Probes)
	lineage.AggregateDataSHA256 = restoreproof.AggregateDataSHA256(lineage.Probes)
	lineage.ProviderAbsenceSetSHA256 = restoreproof.ProviderAbsenceSetSHA256(lineage.BackendArtifacts)
	lineage.EvidenceSHA256 = restoreproof.DataLineageEvidenceSHA256(&lineage)
	receipt := restoreproof.VolumeReceipt{
		SchemaVersion:    restoreproof.ReceiptSchemaVersion,
		ProofScope:       restoreproof.ScopeSingleVolumeDataPath,
		VeleroVersion:    restoreproof.VeleroVersion,
		VeleroRuntime:    veleroRuntime,
		CollectedAt:      maxCanonicalTimestamp(clock.Now(), verifiedAt),
		Context:          contextProof,
		Lineage:          lineage,
		DataUpload:       dataUploadProof,
		DataUploadResult: resultProof,
	}
	restoreproof.SortReceiptCanonical(&receipt)
	receipt.ReceiptSHA256 = restoreproof.ReceiptSHA256(receipt)
	if err := restoreproof.ValidateCSIDataMoverVolumeReceipt(&receipt); err != nil {
		return restoreproof.VolumeReceipt{}, fmt.Errorf("collected restore proof failed validation: %w", err)
	}
	return receipt, nil
}

func readRestore(ctx context.Context, reader KubernetesReader, request CollectionRequest) (Restore, error) {
	payload, err := reader.Get(ctx, restoreproof.VeleroV1RestoreGVR, request.VeleroNamespace, request.RestoreName)
	if err != nil {
		return Restore{}, errors.New("read Velero Restore")
	}
	restoreObject, err := DecodeRestore(payload)
	if err != nil || restoreObject.Identity.Metadata.Name != request.RestoreName || restoreObject.Identity.Metadata.Namespace != request.VeleroNamespace ||
		restoreObject.Spec.ScheduleName != "" || len(restoreObject.Spec.NamespaceMapping) != 1 || restoreObject.Spec.NamespaceMapping[request.SourceNamespace] != request.TargetNamespace ||
		!validRestoreUploaderConfig(restoreObject.Spec.UploaderConfig) ||
		restoreObject.Status.Phase != "Completed" || restoreObject.Status.Errors != 0 || restoreObject.Status.Warnings != 0 ||
		!canonicalTime(restoreObject.Status.StartTimestamp) || !canonicalTime(restoreObject.Status.CompletionTimestamp) {
		return Restore{}, errors.New("Velero Restore is not an exact completed copy restore")
	}
	return restoreObject, nil
}

func readVeleroRuntime(ctx context.Context, reader KubernetesReader, request CollectionRequest, restoreObject Restore, clock Clock) (restoreproof.VeleroRuntimeAttestation, error) {
	payload, err := reader.Get(ctx, restoreproof.VeleroV1ServerStatusRequestGVR, request.VeleroNamespace, request.ServerStatusRequestName)
	if err != nil {
		return restoreproof.VeleroRuntimeAttestation{}, errors.New("read Velero ServerStatusRequest")
	}
	status, err := DecodeServerStatusRequest(payload)
	if err != nil || status.Identity.Metadata.Name != request.ServerStatusRequestName || status.Identity.Metadata.Namespace != request.VeleroNamespace ||
		restoreproof.SHA256(status.Identity.Metadata.UID) != request.ServerStatusRequestUIDSHA256 || status.Status.Phase != "Processed" ||
		status.Status.ServerVersion != restoreproof.VeleroVersion || !canonicalTime(status.Status.ProcessedTimestamp) {
		return restoreproof.VeleroRuntimeAttestation{}, errors.New("Velero ServerStatusRequest is invalid")
	}
	processedAt, _ := time.Parse(time.RFC3339Nano, status.Status.ProcessedTimestamp)
	restoreCompleted, _ := time.Parse(time.RFC3339Nano, restoreObject.Status.CompletionTimestamp)
	observedAt := clock.Now().UTC()
	if !processedAt.After(restoreCompleted) || observedAt.Before(processedAt.Add(-serverStatusAllowedFutureSkew)) || observedAt.After(processedAt.Add(serverStatusMaximumAge)) {
		return restoreproof.VeleroRuntimeAttestation{}, errors.New("Velero ServerStatusRequest is stale or outside the restore timeline")
	}
	attestation := restoreproof.VeleroRuntimeAttestation{
		GVR:           restoreproof.VeleroV1ServerStatusRequestGVR,
		Object:        targetPointer(status.Identity.Target("serverstatusrequests.velero.io")),
		ServerVersion: status.Status.ServerVersion,
		Phase:         status.Status.Phase,
		ProcessedAt:   status.Status.ProcessedTimestamp,
		ObservedAt:    canonicalTimestamp(observedAt),
		EvidenceRef:   request.EvidencePrefix + "/velero-server-status",
	}
	attestation.EvidenceSHA256 = restoreproof.VeleroRuntimeEvidenceSHA256(attestation)
	return attestation, nil
}

func readBackup(ctx context.Context, reader KubernetesReader, request CollectionRequest, restoreObject Restore) (Backup, error) {
	payload, err := reader.Get(ctx, restoreproof.VeleroV1BackupGVR, request.VeleroNamespace, restoreObject.Spec.BackupName)
	if err != nil {
		return Backup{}, errors.New("read Velero Backup")
	}
	backupObject, err := DecodeBackup(payload)
	if err != nil || backupObject.Identity.Metadata.Name != restoreObject.Spec.BackupName || backupObject.Identity.Metadata.Namespace != request.VeleroNamespace ||
		backupObject.Identity.Metadata.Labels["velero.io/schedule-name"] != "" || !backupObject.Spec.SnapshotMoveData || !builtInDataMover(backupObject.Spec.DataMover) ||
		!validBackupUploaderConfig(backupObject.Spec.UploaderConfig) ||
		backupObject.Status.Phase != "Completed" || backupObject.Status.Errors != 0 || backupObject.Status.Warnings != 0 || !canonicalTime(backupObject.Status.CompletionTimestamp) {
		return Backup{}, errors.New("Velero Backup is not an exact completed direct data-mover backup")
	}
	if duration, durationErr := time.ParseDuration(backupObject.Spec.CSISnapshotTimeout); durationErr != nil || duration <= 0 {
		return Backup{}, errors.New("Velero Backup CSI snapshot timeout is invalid")
	}
	return backupObject, nil
}

func readPVCLineage(ctx context.Context, reader KubernetesReader, request CollectionRequest, baseline restoreproof.SourceBaseline) (PersistentVolumeClaim, PersistentVolume, PersistentVolumeClaim, PersistentVolume, restoreproof.SourceResource, error) {
	sourceBytes, err := reader.Get(ctx, restoreproof.CoreV1PVCGVR, request.SourceNamespace, request.SourcePVC)
	if err != nil {
		return PersistentVolumeClaim{}, PersistentVolume{}, PersistentVolumeClaim{}, PersistentVolume{}, restoreproof.SourceResource{}, errors.New("read source PVC")
	}
	sourcePVC, err := DecodePersistentVolumeClaim(sourceBytes)
	if err != nil || sourcePVC.Identity.Metadata.Namespace != request.SourceNamespace || sourcePVC.Identity.Metadata.Name != request.SourcePVC || sourcePVC.Spec.VolumeName == "" {
		return PersistentVolumeClaim{}, PersistentVolume{}, PersistentVolumeClaim{}, PersistentVolume{}, restoreproof.SourceResource{}, errors.New("source PVC identity is invalid")
	}
	sourceProof := baseline.Source
	sourceProof.ResourceVersionAfterSHA256 = restoreproof.SHA256(sourcePVC.Identity.Metadata.ResourceVersion)
	sourceProof.StateAfterSHA256 = sourcePVC.Identity.ProofStateSHA256
	if sourceProof.UIDSHA256 != restoreproof.SHA256(sourcePVC.Identity.Metadata.UID) || sourceProof.StateBeforeSHA256 != sourceProof.StateAfterSHA256 {
		return PersistentVolumeClaim{}, PersistentVolume{}, PersistentVolumeClaim{}, PersistentVolume{}, restoreproof.SourceResource{}, errors.New("source PVC changed after baseline")
	}
	sourcePVBytes, err := reader.Get(ctx, restoreproof.CoreV1PVGVR, "", sourcePVC.Spec.VolumeName)
	if err != nil {
		return PersistentVolumeClaim{}, PersistentVolume{}, PersistentVolumeClaim{}, PersistentVolume{}, restoreproof.SourceResource{}, errors.New("read source PV")
	}
	sourcePV, err := DecodePersistentVolume(sourcePVBytes)
	if err != nil || sourcePV.Identity.Metadata.Namespace != "" || sourcePV.Identity.Metadata.Name != sourcePVC.Spec.VolumeName || sourcePV.Spec.ClaimRef == nil ||
		sourcePV.Spec.ClaimRef.Namespace != request.SourceNamespace || sourcePV.Spec.ClaimRef.Name != request.SourcePVC || sourcePV.Spec.ClaimRef.UID != sourcePVC.Identity.Metadata.UID ||
		sourcePV.Spec.CSI == nil || !validRuntimeID(sourcePV.Spec.CSI.Driver) || sourcePV.Spec.CSI.VolumeHandle == "" {
		return PersistentVolumeClaim{}, PersistentVolume{}, PersistentVolumeClaim{}, PersistentVolume{}, restoreproof.SourceResource{}, errors.New("source PV lineage is invalid")
	}
	targetBytes, err := reader.Get(ctx, restoreproof.CoreV1PVCGVR, request.TargetNamespace, request.TargetPVC)
	if err != nil {
		return PersistentVolumeClaim{}, PersistentVolume{}, PersistentVolumeClaim{}, PersistentVolume{}, restoreproof.SourceResource{}, errors.New("read restored PVC")
	}
	targetPVC, err := DecodePersistentVolumeClaim(targetBytes)
	if err != nil || targetPVC.Identity.Metadata.Namespace != request.TargetNamespace || targetPVC.Identity.Metadata.Name != request.TargetPVC || targetPVC.Spec.VolumeName == "" ||
		sourcePVC.Identity.Metadata.Name != targetPVC.Identity.Metadata.Name || sourcePVC.Identity.Metadata.UID == targetPVC.Identity.Metadata.UID {
		return PersistentVolumeClaim{}, PersistentVolume{}, PersistentVolumeClaim{}, PersistentVolume{}, restoreproof.SourceResource{}, errors.New("restored PVC lineage is invalid")
	}
	pvBytes, err := reader.Get(ctx, restoreproof.CoreV1PVGVR, "", targetPVC.Spec.VolumeName)
	if err != nil {
		return PersistentVolumeClaim{}, PersistentVolume{}, PersistentVolumeClaim{}, PersistentVolume{}, restoreproof.SourceResource{}, errors.New("read restored PV")
	}
	targetPV, err := DecodePersistentVolume(pvBytes)
	if err != nil || targetPV.Identity.Metadata.Namespace != "" || targetPV.Identity.Metadata.Name != targetPVC.Spec.VolumeName || targetPV.Spec.ClaimRef == nil ||
		targetPV.Spec.ClaimRef.Namespace != request.TargetNamespace || targetPV.Spec.ClaimRef.Name != request.TargetPVC || targetPV.Spec.ClaimRef.UID != targetPVC.Identity.Metadata.UID ||
		targetPV.Spec.CSI == nil || !validRuntimeID(targetPV.Spec.CSI.Driver) || targetPV.Spec.CSI.VolumeHandle == "" ||
		targetPV.Identity.Metadata.Name == sourcePV.Identity.Metadata.Name || targetPV.Identity.Metadata.UID == sourcePV.Identity.Metadata.UID ||
		targetPV.Spec.CSI.Driver != sourcePV.Spec.CSI.Driver || restoreproof.SHA256(targetPV.Spec.CSI.VolumeHandle) == restoreproof.SHA256(sourcePV.Spec.CSI.VolumeHandle) {
		return PersistentVolumeClaim{}, PersistentVolume{}, PersistentVolumeClaim{}, PersistentVolume{}, restoreproof.SourceResource{}, errors.New("restored PV lineage is invalid")
	}
	return sourcePVC, sourcePV, targetPVC, targetPV, sourceProof, nil
}

func findDataUpload(ctx context.Context, reader KubernetesReader, request CollectionRequest, backupObject Backup, sourcePVC PersistentVolumeClaim, archived DataUpload) (DataUpload, error) {
	selector := "velero.io/backup-name=" + veleroValidLabelName(backupObject.Identity.Metadata.Name)
	items, err := listAll(ctx, reader, restoreproof.DataUploadGVR, request.VeleroNamespace, selector, "velero.io/v2alpha1", "DataUploadList")
	if err != nil {
		return DataUpload{}, errors.New("list retained Velero DataUploads")
	}
	var matches []DataUpload
	for _, item := range items {
		upload, decodeErr := DecodeDataUpload(item)
		if decodeErr != nil {
			return DataUpload{}, errors.New("decode retained Velero DataUpload")
		}
		if upload.Identity.Metadata.Name == request.DataUploadName && upload.Spec.SourceNamespace == request.SourceNamespace && upload.Spec.SourcePVC == request.SourcePVC {
			matches = append(matches, upload)
		}
	}
	if len(matches) != 1 || !sameDataUpload(matches[0], archived) || matches[0].Identity.Metadata.Labels["velero.io/pvc-uid"] != sourcePVC.Identity.Metadata.UID {
		return DataUpload{}, errors.New("retained and archived DataUpload identity is not exact")
	}
	return matches[0], nil
}

func readObservedDataUploadResult(request CollectionRequest, restoreObject Restore, sourceProof restoreproof.SourceResource) (ConfigMap, string, DataUploadResult, string, error) {
	if request.DataUploadResultObservation == nil {
		return ConfigMap{}, "", DataUploadResult{}, "", errors.New("Velero DataUploadResult observation is missing")
	}
	observation := *request.DataUploadResultObservation
	if err := validateDataUploadResultObservation(observation); err != nil {
		return ConfigMap{}, "", DataUploadResult{}, "", err
	}
	observationRequest := DataUploadResultObservationRequest{
		SchemaVersion:   DataUploadResultObservationRequestSchemaVersion,
		VeleroNamespace: request.VeleroNamespace, RestoreName: request.RestoreName,
		SourceNamespace: request.SourceNamespace, SourcePVC: request.SourcePVC,
		DataUploadName: request.DataUploadName, EvidencePrefix: request.EvidencePrefix,
	}
	if observation.RequestSHA256 != requestJSONSHA256(observationRequest) || observation.EvidenceRef != request.EvidencePrefix+"/velero-data-upload-result-observation" {
		return ConfigMap{}, "", DataUploadResult{}, "", errors.New("Velero DataUploadResult observation request binding is invalid")
	}
	restoreUID := restoreObject.Identity.Metadata.UID
	configMap, err := DecodeConfigMap(observation.Object)
	if err != nil || configMap.Identity.Metadata.Namespace != request.VeleroNamespace || len(configMap.Data) != 1 {
		return ConfigMap{}, "", DataUploadResult{}, "", errors.New("decode observed Velero DataUploadResult ConfigMap")
	}
	payload, exists := configMap.Data[restoreUID]
	if !exists {
		return ConfigMap{}, "", DataUploadResult{}, "", errors.New("observed Velero DataUploadResult key is missing")
	}
	result, err := DecodeDataUploadResult([]byte(payload))
	if err != nil || sourceProof.Namespace != result.SourceNamespace {
		return ConfigMap{}, "", DataUploadResult{}, "", errors.New("decode observed Velero DataUploadResult payload")
	}
	// Keep clock domains separate: observation.ObservedAt is the API-server
	// creationTimestamp, while Restore status timestamps are written by the
	// Velero controller. UID/request/object bindings establish causality; only
	// the controller timestamps are ordered against each other here.
	restoreStarted, startedErr := time.Parse(time.RFC3339Nano, restoreObject.Status.StartTimestamp)
	restoreCompleted, completedErr := time.Parse(time.RFC3339Nano, restoreObject.Status.CompletionTimestamp)
	if startedErr != nil || completedErr != nil || !canonicalTime(restoreObject.Identity.Metadata.CreationTimestamp) ||
		!restoreStarted.Before(restoreCompleted) || configMap.Identity.Metadata.CreationTimestamp != observation.ObservedAt {
		return ConfigMap{}, "", DataUploadResult{}, "", errors.New("Velero DataUploadResult observation is outside the Restore timeline")
	}
	return configMap, payload, result, observation.ObservedAt, nil
}

func confirmVeleroAutoDeletedDataUploadResult(ctx context.Context, reader KubernetesReader, request CollectionRequest, configMap ConfigMap, restoreObject Restore, clock Clock) (string, error) {
	target := observedTarget{GVR: restoreproof.CoreV1CMGVR, Namespace: request.VeleroNamespace, Name: configMap.Identity.Metadata.Name, Proof: configMap.Identity.Target("configmaps")}
	if err := requireExactAbsentObservedTarget(ctx, reader, target); err != nil {
		return "", errors.New("Velero DataUploadResult auto-deletion was not confirmed")
	}
	// The terminal Restore was read before this exact absence check, which is
	// the causal proof. The watcher and collector can be separate processes, so
	// their local timestamps must not be ordered against each other.
	confirmedAt := canonicalTimestamp(clock.Now())
	started, startedErr := time.Parse(time.RFC3339Nano, restoreObject.Status.StartTimestamp)
	completed, completedErr := time.Parse(time.RFC3339Nano, restoreObject.Status.CompletionTimestamp)
	_, confirmedErr := time.Parse(time.RFC3339Nano, confirmedAt)
	if startedErr != nil || completedErr != nil || confirmedErr != nil || restoreObject.Status.Phase != "Completed" || !started.Before(completed) {
		return "", errors.New("Velero DataUploadResult auto-deletion timeline is invalid")
	}
	return confirmedAt, nil
}

func requireExactAbsentObservedTarget(ctx context.Context, reader KubernetesReader, target observedTarget) error {
	if _, err := reader.Get(ctx, target.GVR, target.Namespace, target.Name); !errors.Is(err, ErrNotFound) {
		return errors.New("auto-cleaned Kubernetes object is present or unreadable")
	}
	absent, err := reader.ConfirmAbsent(ctx, target.GVR, target.Namespace, target.Name)
	if err != nil || !absent {
		return errors.New("auto-cleaned Kubernetes object absence is unconfirmed")
	}
	return nil
}

func findDataDownload(ctx context.Context, reader KubernetesReader, request CollectionRequest, restoreObject Restore, targetPVC PersistentVolumeClaim, result DataUploadResult) (DataDownload, error) {
	selector := "velero.io/restore-uid=" + veleroValidLabelName(restoreObject.Identity.Metadata.UID)
	items, err := listAll(ctx, reader, restoreproof.DataDownloadGVR, request.VeleroNamespace, selector, "velero.io/v2alpha1", "DataDownloadList")
	if err != nil {
		return DataDownload{}, errors.New("list Velero DataDownloads")
	}
	var matches []DataDownload
	for _, item := range items {
		dataDownload, decodeErr := DecodeDataDownload(item)
		if decodeErr != nil {
			return DataDownload{}, errors.New("decode Velero DataDownload")
		}
		if dataDownload.Spec.TargetVolume.Namespace == request.TargetNamespace && dataDownload.Spec.TargetVolume.PVC == targetPVC.Identity.Metadata.Name {
			matches = append(matches, dataDownload)
		}
	}
	if len(matches) != 1 || matches[0].Spec.SnapshotID != result.SnapshotID {
		return DataDownload{}, errors.New("find exact Velero DataDownload")
	}
	return matches[0], nil
}

func crossValidateDataPath(request CollectionRequest, restoreObject Restore, backupObject Backup, sourcePVC PersistentVolumeClaim, sourcePV PersistentVolume, targetPVC PersistentVolumeClaim, targetPV PersistentVolume, liveUpload, archivedUpload DataUpload, resultConfigMap ConfigMap, result DataUploadResult, dataDownload DataDownload) error {
	backupUID := backupObject.Identity.Metadata.UID
	restoreUID := restoreObject.Identity.Metadata.UID
	uploadOwner, uploadOwnerOK := controllerOwner(liveUpload.Identity.Metadata.OwnerReferences, "velero.io/v1", "Backup", backupObject.Identity.Metadata.Name)
	downloadOwner, downloadOwnerOK := controllerOwner(dataDownload.Identity.Metadata.OwnerReferences, "velero.io/v1", "Restore", restoreObject.Identity.Metadata.Name)
	operationID := dataDownload.Identity.Metadata.Labels["velero.io/async-operation-id"]
	sourceStorageClass := ""
	if sourcePVC.Spec.StorageClassName != nil {
		sourceStorageClass = *sourcePVC.Spec.StorageClassName
	}
	uploadCompleted, uploadCompletedErr := time.Parse(time.RFC3339Nano, liveUpload.Status.CompletionTimestamp)
	uploadStarted, uploadStartedErr := time.Parse(time.RFC3339Nano, liveUpload.Status.StartTimestamp)
	backupCompleted, backupCompletedErr := time.Parse(time.RFC3339Nano, backupObject.Status.CompletionTimestamp)
	restoreStarted, restoreStartedErr := time.Parse(time.RFC3339Nano, restoreObject.Status.StartTimestamp)
	restoreCompleted, restoreCompletedErr := time.Parse(time.RFC3339Nano, restoreObject.Status.CompletionTimestamp)
	downloadStarted, downloadStartedErr := time.Parse(time.RFC3339Nano, dataDownload.Status.StartTimestamp)
	downloadCompleted, downloadCompletedErr := time.Parse(time.RFC3339Nano, dataDownload.Status.CompletionTimestamp)
	if !uploadOwnerOK || uploadOwner.UID != backupUID || liveUpload.Identity.Metadata.Labels["velero.io/backup-name"] != veleroValidLabelName(backupObject.Identity.Metadata.Name) ||
		liveUpload.Identity.Metadata.Labels["velero.io/backup-uid"] != backupUID || liveUpload.Identity.Metadata.Labels["velero.io/pvc-uid"] != sourcePVC.Identity.Metadata.UID ||
		liveUpload.Identity.Metadata.Labels["velero.io/async-operation-id"] == "" || liveUpload.Spec.SnapshotType != "CSI" || liveUpload.Spec.CSISnapshot == nil ||
		liveUpload.Spec.CSISnapshot.VolumeSnapshot == "" || sourceStorageClass == "" || liveUpload.Spec.CSISnapshot.StorageClass != sourceStorageClass ||
		liveUpload.Spec.CSISnapshot.Driver != targetPV.Spec.CSI.Driver || targetPV.Spec.CSI.Driver != sourcePV.Spec.CSI.Driver || !validRuntimeID(targetPV.Spec.CSI.Driver) ||
		liveUpload.Spec.BackupStorageLocation != backupObject.Spec.StorageLocation || !builtInDataMover(liveUpload.Spec.DataMover) || liveUpload.Spec.Cancel ||
		liveUpload.Spec.OperationTimeout != backupObject.Spec.CSISnapshotTimeout || !sameStringMap(liveUpload.Spec.DataMoverConfig, expectedBackupUploaderConfig(backupObject.Spec.UploaderConfig)) ||
		liveUpload.Status.Phase != "Completed" || liveUpload.Status.Message != "" || liveUpload.Status.SnapshotID == "" || liveUpload.Status.NodeOS != "linux" ||
		uploadStartedErr != nil || uploadCompletedErr != nil || backupCompletedErr != nil || restoreStartedErr != nil || restoreCompletedErr != nil ||
		downloadStartedErr != nil || downloadCompletedErr != nil || !canonicalTime(liveUpload.Status.StartTimestamp) || !canonicalTime(liveUpload.Status.CompletionTimestamp) ||
		!canonicalTime(dataDownload.Status.StartTimestamp) || !canonicalTime(dataDownload.Status.CompletionTimestamp) ||
		!uploadStarted.Before(uploadCompleted) || uploadCompleted.After(backupCompleted) || backupCompleted.After(restoreStarted) ||
		!restoreStarted.Before(restoreCompleted) || downloadStarted.Before(restoreStarted) || !downloadStarted.Before(downloadCompleted) || downloadCompleted.After(restoreCompleted) ||
		liveUpload.Status.Progress.TotalBytes <= 0 || liveUpload.Status.Progress.BytesDone != liveUpload.Status.Progress.TotalBytes ||
		!downloadOwnerOK || downloadOwner.UID != restoreUID || operationID == "" || dataDownload.Identity.Metadata.Labels["velero.io/restore-name"] != veleroValidLabelName(restoreObject.Identity.Metadata.Name) ||
		dataDownload.Identity.Metadata.Labels["velero.io/restore-uid"] != restoreUID || dataDownload.Spec.TargetVolume.PVC != targetPVC.Identity.Metadata.Name ||
		dataDownload.Spec.TargetVolume.PV != "" || dataDownload.Spec.TargetVolume.Namespace != request.TargetNamespace || dataDownload.Spec.BackupStorageLocation != backupObject.Spec.StorageLocation ||
		!builtInDataMover(dataDownload.Spec.DataMover) || dataDownload.Spec.SnapshotID != result.SnapshotID || dataDownload.Spec.SourceNamespace != request.SourceNamespace ||
		dataDownload.Spec.OperationTimeout != backupObject.Spec.CSISnapshotTimeout || !sameStringMap(dataDownload.Spec.DataMoverConfig, expectedRestoreUploaderConfig(restoreObject.Spec.UploaderConfig)) ||
		dataDownload.Spec.Cancel || dataDownload.Spec.NodeOS != "linux" || dataDownload.Spec.SnapshotSize != liveUpload.Status.Progress.TotalBytes ||
		dataDownload.Status.Phase != "Completed" || dataDownload.Status.Progress.BytesDone != dataDownload.Status.Progress.TotalBytes || dataDownload.Status.Progress.TotalBytes != dataDownload.Spec.SnapshotSize ||
		resultConfigMap.Identity.Metadata.Labels["velero.io/restore-uid"] != veleroValidLabelName(restoreUID) ||
		resultConfigMap.Identity.Metadata.Labels["velero.io/pvc-namespace-name"] != veleroValidLabelName(request.SourceNamespace+"."+request.SourcePVC) ||
		resultConfigMap.Identity.Metadata.Labels["velero.io/resource-usage"] != "DataUpload" || !strings.HasPrefix(resultConfigMap.Identity.Metadata.Name, liveUpload.Identity.Metadata.Name+"-") ||
		result.BackupStorageLocation != backupObject.Spec.StorageLocation ||
		result.DataMover != liveUpload.Spec.DataMover || result.SnapshotID != liveUpload.Status.SnapshotID || result.SourceNamespace != request.SourceNamespace ||
		result.SnapshotSize != liveUpload.Status.Progress.TotalBytes || result.NodeOS != liveUpload.Status.NodeOS || !sameStringMap(result.DataMoverResult, liveUpload.Status.DataMoverResult) ||
		!sameDataUpload(liveUpload, archivedUpload) {
		return errors.New("Velero CSI data-mover object lineage is invalid")
	}
	return nil
}

type observedTarget struct {
	GVR       restoreproof.GVR
	Namespace string
	Name      string
	Proof     restoreproof.TargetResource
}

func waitForExactCleanup(ctx context.Context, reader KubernetesReader, targets []observedTarget, request CollectionRequest, clock Clock) (string, error) {
	timeout := request.CleanupTimeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	poll := request.PollInterval
	if poll <= 0 {
		poll = 2 * time.Second
	}
	cleanupContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline := clock.Now().Add(timeout)
	for {
		if !clock.Now().Before(deadline) {
			return "", errors.New("Kubernetes restore cleanup timed out")
		}
		allAbsent, err := requireExactCleanup(cleanupContext, reader, targets)
		if err != nil {
			return "", errors.New("observe Kubernetes restore cleanup")
		}
		if allAbsent {
			return canonicalTimestamp(clock.Now()), nil
		}
		remaining := deadline.Sub(clock.Now())
		wait := poll
		if wait > remaining {
			wait = remaining
		}
		if wait <= 0 || clock.Wait(cleanupContext, wait) != nil {
			return "", errors.New("Kubernetes restore cleanup interrupted")
		}
	}
}

func requireExactCleanup(ctx context.Context, reader KubernetesReader, targets []observedTarget) (bool, error) {
	for _, target := range targets {
		payload, err := reader.Get(ctx, target.GVR, target.Namespace, target.Name)
		if errors.Is(err, ErrNotFound) {
			absent, confirmErr := reader.ConfirmAbsent(ctx, target.GVR, target.Namespace, target.Name)
			if confirmErr != nil || !absent {
				return false, errors.New("cleanup target absence was not confirmed by its exact collection")
			}
			continue
		}
		if err != nil {
			return false, err
		}
		identity, decodeErr := decodeCleanupIdentity(payload, target)
		if decodeErr != nil {
			return false, decodeErr
		}
		if identity.Metadata.UID != "" && restoreproof.SHA256(identity.Metadata.UID) != target.Proof.UIDSHA256 {
			return false, errors.New("cleanup target was replaced")
		}
		return false, nil
	}
	return true, nil
}

func fenceProofRelevantCleanupTargets(ctx context.Context, reader KubernetesReader, targets []observedTarget) error {
	for _, target := range targets {
		payload, err := reader.Get(ctx, target.GVR, target.Namespace, target.Name)
		if err != nil {
			return errors.New("read cleanup target before readiness")
		}
		identity, decodeErr := decodeCleanupIdentity(payload, target)
		if decodeErr != nil || identity.Metadata.DeletionTimestamp != nil && strings.TrimSpace(*identity.Metadata.DeletionTimestamp) != "" ||
			restoreproof.SHA256(identity.Metadata.UID) != target.Proof.UIDSHA256 ||
			identity.ProofStateSHA256 != target.Proof.ValidatedStateSHA256 {
			return errors.New("cleanup target identity changed before readiness")
		}
	}
	return nil
}

func decodeCleanupIdentity(payload []byte, target observedTarget) (Identity, error) {
	expectedAPIVersion := target.GVR.Version
	if target.GVR.Group != "" {
		expectedAPIVersion = target.GVR.Group + "/" + target.GVR.Version
	}
	expectedKind := map[string]string{
		"persistentvolumeclaims":  "PersistentVolumeClaim",
		"persistentvolumes":       "PersistentVolume",
		"datadownloads.velero.io": "DataDownload",
		"configmaps":              "ConfigMap",
	}[target.Proof.Resource]
	var envelope objectEnvelope
	if expectedKind == "" || strictjson.Decode(payload, &envelope) != nil || envelope.APIVersion != expectedAPIVersion || envelope.Kind != expectedKind ||
		envelope.Metadata.Name != target.Name || envelope.Metadata.Namespace != target.Namespace || envelope.Metadata.UID == "" || envelope.Metadata.ResourceVersion == "" {
		return Identity{}, errors.New("cleanup target identity is invalid")
	}
	var raw map[string]any
	if strictjson.Decode(payload, &raw) != nil {
		return Identity{}, errors.New("cleanup target state is invalid")
	}
	stateSHA256, err := restoreproof.CanonicalKubernetesStateSHA256(raw)
	if err != nil {
		return Identity{}, errors.New("cleanup target state is invalid")
	}
	proofStateSHA256, err := proofRelevantKubernetesStateSHA256(raw, expectedKind)
	if err != nil {
		return Identity{}, errors.New("cleanup target proof state is invalid")
	}
	return Identity{Metadata: envelope.Metadata, StateSHA256: stateSHA256, ProofStateSHA256: proofStateSHA256, Raw: raw}, nil
}

func sourceStillUnchanged(ctx context.Context, reader KubernetesReader, request CollectionRequest, baseline restoreproof.SourceBaseline, sourcePVProof restoreproof.SourceResource) error {
	payload, err := reader.Get(ctx, restoreproof.CoreV1PVCGVR, request.SourceNamespace, request.SourcePVC)
	if err != nil {
		return errors.New("read source PVC continuity fence")
	}
	pvc, err := DecodePersistentVolumeClaim(payload)
	if err != nil || restoreproof.SHA256(pvc.Identity.Metadata.UID) != baseline.Source.UIDSHA256 ||
		pvc.Identity.ProofStateSHA256 != baseline.Source.StateBeforeSHA256 {
		return errors.New("source PVC changed from its baseline")
	}
	pvPayload, err := reader.Get(ctx, restoreproof.CoreV1PVGVR, "", sourcePVProof.Name)
	if err != nil {
		return errors.New("read source PV continuity fence")
	}
	pv, err := DecodePersistentVolume(pvPayload)
	if err != nil || restoreproof.SHA256(pv.Identity.Metadata.UID) != sourcePVProof.UIDSHA256 ||
		pv.Identity.ProofStateSHA256 != sourcePVProof.StateBeforeSHA256 {
		return errors.New("source PV changed during restore-proof collection")
	}
	return nil
}

func observeProbe(ctx context.Context, observer ProbeObserver, request ProbeRequest, clock Clock) (ProbeObservation, error) {
	challenge, err := newChallenge()
	if err != nil || !validSHA256(request.AdapterExecutableSHA256) || request.AdapterExecutableSHA256 != observer.IdentitySHA256() {
		return ProbeObservation{}, errors.New("prepare data probe adapter request")
	}
	request.Challenge = challenge
	requestSHA256 := adapterRequestSHA256(request)
	startedAt := clock.Now().UTC()
	observed, err := observer.Observe(ctx, request)
	completedAt := clock.Now().UTC()
	if err != nil || !validProbeObservation(observed) || observed.RequestSHA256 != requestSHA256 ||
		observed.AdapterExecutableSHA256 != request.AdapterExecutableSHA256 ||
		!timestampWithin(observed.StartedAt, startedAt, completedAt, 30*time.Second) || !timestampWithin(observed.CompletedAt, startedAt, completedAt, 30*time.Second) {
		return ProbeObservation{}, errors.New("data probe adapter response is not bound to its invocation")
	}
	return observed, nil
}

func observeBackend(ctx context.Context, observer BackendObserver, rawHandle string, clock Clock) (BackendObservation, error) {
	challenge, err := newChallenge()
	identity := observer.IdentitySHA256()
	if err != nil || !validSHA256(identity) {
		return BackendObservation{}, errors.New("prepare provider adapter request")
	}
	request := BackendRequest{
		SchemaVersion:                 AdapterRequestSchemaVersion,
		RequestDigestCanonicalization: AdapterRequestCanonicalization,
		Challenge:                     challenge,
		AdapterExecutableSHA256:       identity,
		Operation:                     "observe",
		SourceKind:                    "persistent-volume",
		ArtifactHandle:                rawHandle,
		ArtifactHandleSHA256:          restoreproof.SHA256(rawHandle),
	}
	requestSHA256 := adapterRequestSHA256(request)
	startedAt := clock.Now().UTC()
	observed, err := observer.Observe(ctx, request)
	completedAt := clock.Now().UTC()
	if err != nil || !validBackendObservation(observed) || observed.RequestSHA256 != requestSHA256 ||
		observed.AdapterExecutableSHA256 != identity || observed.ArtifactHandleSHA256 != request.ArtifactHandleSHA256 ||
		!timestampWithin(observed.ObservedAt, startedAt, completedAt, 30*time.Second) {
		return BackendObservation{}, errors.New("provider adapter response is not bound to its invocation")
	}
	return observed, nil
}

func observeAbsence(ctx context.Context, observer BackendObserver, rawHandle string, backend restoreproof.BackendArtifactLineage, querySHA256 string, clock Clock) (restoreproof.ProviderAbsenceObservation, error) {
	observed, err := observeBackend(ctx, observer, rawHandle, clock)
	if err != nil || observed.Present == nil || *observed.Present || observed.Implementation != backend.ProviderImplementation || observed.Version != backend.ProviderVersion {
		return restoreproof.ProviderAbsenceObservation{}, errors.New("provider artifact absence observation failed")
	}
	return *providerObservationProof(observed, "absent", querySHA256), nil
}

func providerObservationProof(observed BackendObservation, status, querySHA256 string) *restoreproof.ProviderObservation {
	observation := &restoreproof.ProviderObservation{
		Status:                  status,
		ArtifactHandleSHA256:    observed.ArtifactHandleSHA256,
		ObservedAt:              observed.ObservedAt,
		RequestSHA256:           observed.RequestSHA256,
		AdapterExecutableSHA256: observed.AdapterExecutableSHA256,
		QuerySHA256:             querySHA256,
		EvidenceRef:             observed.EvidenceRef,
		EvidenceSHA256:          observed.EvidenceSHA256,
	}
	observation.ObservationSHA256 = restoreproof.ProviderObservationSHA256(querySHA256, observation.RequestSHA256, observation.AdapterExecutableSHA256, status, observation.ObservedAt)
	return observation
}

func buildDataUploadProof(request CollectionRequest, backup Backup, source restoreproof.SourceResource, archivedSHA string, retained DataUpload, retainedAt string) restoreproof.DataUploadProof {
	owner, _ := controllerOwner(retained.Identity.Metadata.OwnerReferences, "velero.io/v1", "Backup", backup.Identity.Metadata.Name)
	proof := restoreproof.DataUploadProof{
		GVR:                           restoreproof.DataUploadGVR,
		Namespace:                     retained.Identity.Metadata.Namespace,
		Name:                          retained.Identity.Metadata.Name,
		UIDSHA256:                     restoreproof.SHA256(retained.Identity.Metadata.UID),
		ResourceVersionSHA256:         restoreproof.SHA256(retained.Identity.Metadata.ResourceVersion),
		OwnerBackupUIDSHA256:          restoreproof.SHA256(owner.UID),
		BackupNameLabel:               retained.Identity.Metadata.Labels["velero.io/backup-name"],
		BackupUIDLabelSHA256:          restoreproof.SHA256(retained.Identity.Metadata.Labels["velero.io/backup-uid"]),
		SourcePVCUIDLabelSHA256:       restoreproof.SHA256(retained.Identity.Metadata.Labels["velero.io/pvc-uid"]),
		SourcePVCGVR:                  restoreproof.CoreV1PVCGVR,
		SourcePVC:                     sourcePointer(source),
		SnapshotType:                  retained.Spec.SnapshotType,
		VolumeSnapshotSHA256:          restoreproof.SHA256(retained.Spec.CSISnapshot.VolumeSnapshot),
		StorageClassSHA256:            restoreproof.SHA256(retained.Spec.CSISnapshot.StorageClass),
		SnapshotClassSHA256:           optionalValueSHA256(retained.Spec.CSISnapshot.SnapshotClass),
		Driver:                        retained.Spec.CSISnapshot.Driver,
		BackupStorageLocation:         retained.Spec.BackupStorageLocation,
		DataMover:                     retained.Spec.DataMover,
		DataMoverConfigSHA256:         optionalMapSHA256(retained.Spec.DataMoverConfig),
		OperationIDSHA256:             restoreproof.SHA256(retained.Identity.Metadata.Labels["velero.io/async-operation-id"]),
		OperationTimeout:              retained.Spec.OperationTimeout,
		Phase:                         retained.Status.Phase,
		Message:                       retained.Status.Message,
		StartedAt:                     retained.Status.StartTimestamp,
		CompletedAt:                   retained.Status.CompletionTimestamp,
		SnapshotIDSHA256:              restoreproof.SHA256(retained.Status.SnapshotID),
		NodeOS:                        retained.Status.NodeOS,
		DataMoverResultSHA256:         optionalMapSHA256(retained.Status.DataMoverResult),
		BytesDone:                     retained.Status.Progress.BytesDone,
		TotalBytes:                    retained.Status.Progress.TotalBytes,
		ArchivedObjectSHA256:          archivedSHA,
		RetainedAfterRestoreCleanupAt: retainedAt,
		EvidenceRef:                   request.EvidencePrefix + "/velero-data-upload",
	}
	proof.EvidenceSHA256 = restoreproof.DataUploadEvidenceSHA256(&proof)
	return proof
}

func buildDataUploadResultProof(request CollectionRequest, restoreObject Restore, source restoreproof.SourceResource, configMap ConfigMap, result DataUploadResult, upload restoreproof.DataUploadProof, payloadSHA, observedAt, autoDeletedAt string) restoreproof.DataUploadResultProof {
	proof := restoreproof.DataUploadResultProof{
		Status:                   "generated-consumed-velero-cleaned",
		GVR:                      restoreproof.CoreV1CMGVR,
		Object:                   targetPointer(configMap.Identity.Target("configmaps")),
		DataUploadUIDSHA256:      upload.UIDSHA256,
		DataUploadName:           upload.Name,
		ArchivedDataUploadSHA256: upload.ArchivedObjectSHA256,
		RestoreUIDSHA256:         restoreproof.SHA256(restoreObject.Identity.Metadata.UID),
		RestoreUIDLabelSHA256:    restoreproof.SHA256(configMap.Identity.Metadata.Labels["velero.io/restore-uid"]),
		RestoreUIDDataKeySHA256:  restoreproof.SHA256(restoreObject.Identity.Metadata.UID),
		PVCNamespaceNameLabel:    configMap.Identity.Metadata.Labels["velero.io/pvc-namespace-name"],
		ResourceUsage:            configMap.Identity.Metadata.Labels["velero.io/resource-usage"],
		SourcePVC:                sourcePointer(source),
		BackupStorageLocation:    result.BackupStorageLocation,
		DataMover:                result.DataMover,
		SnapshotIDSHA256:         restoreproof.SHA256(result.SnapshotID),
		SourceNamespace:          result.SourceNamespace,
		SnapshotSize:             result.SnapshotSize,
		NodeOS:                   result.NodeOS,
		DataMoverResultSHA256:    optionalMapSHA256(result.DataMoverResult),
		ResultPayloadSHA256:      payloadSHA,
		ObservedAt:               observedAt,
		VeleroAutoDeletedAt:      autoDeletedAt,
		EvidenceRef:              request.EvidencePrefix + "/velero-data-upload-result",
	}
	proof.EvidenceSHA256 = restoreproof.DataUploadResultEvidenceSHA256(&proof)
	return proof
}

func buildProbeProof(source restoreproof.SourceResource, sourcePVC, targetPVC PersistentVolumeClaim, targetPV PersistentVolume, observation ProbeObservation) restoreproof.DataProbe {
	started, _ := time.Parse(time.RFC3339Nano, observation.StartedAt)
	completed, _ := time.Parse(time.RFC3339Nano, observation.CompletedAt)
	return restoreproof.DataProbe{
		Status:                       "verified",
		Implementation:               observation.Implementation,
		Version:                      observation.Version,
		RequestSHA256:                observation.RequestSHA256,
		AdapterExecutableSHA256:      observation.AdapterExecutableSHA256,
		SourceGVR:                    restoreproof.CoreV1PVCGVR,
		Source:                       sourcePointer(source),
		TargetGVR:                    restoreproof.CoreV1PVCGVR,
		Target:                       targetPointer(targetPVC.Identity.Target("persistentvolumeclaims")),
		TargetPV:                     targetPointer(targetPV.Identity.Target("persistentvolumes")),
		SourcePVCVolumeName:          sourcePVC.Spec.VolumeName,
		TargetPVCVolumeName:          targetPV.Identity.Metadata.Name,
		HashAlgorithm:                observation.HashAlgorithm,
		SourceDataSHA256:             observation.SourceSHA256,
		RestoredDataSHA256:           observation.TargetSHA256,
		ValidatedBytes:               observation.ValidatedBytes,
		StartedAt:                    observation.StartedAt,
		CompletedAt:                  observation.CompletedAt,
		ObservedDurationMilliseconds: durationMillisecondsCeiling(completed.Sub(started)),
		EvidenceRef:                  observation.EvidenceRef,
		EvidenceSHA256:               observation.EvidenceSHA256,
	}
}

func buildHelperProof(request CollectionRequest, restoreObject Restore, source restoreproof.SourceResource, targetPVC PersistentVolumeClaim, targetPV PersistentVolume, dataDownload DataDownload, result restoreproof.DataUploadResultProof, upload restoreproof.DataUploadProof) restoreproof.AsyncHelper {
	owner, _ := controllerOwner(dataDownload.Identity.Metadata.OwnerReferences, "velero.io/v1", "Restore", restoreObject.Identity.Metadata.Name)
	operationID := dataDownload.Identity.Metadata.Labels["velero.io/async-operation-id"]
	helper := restoreproof.AsyncHelper{
		GVR:                   restoreproof.DataDownloadGVR,
		Object:                targetPointer(dataDownload.Identity.Target("datadownloads.velero.io")),
		RestoreUIDSHA256:      restoreproof.SHA256(restoreObject.Identity.Metadata.UID),
		OwnerRestoreUIDSHA256: restoreproof.SHA256(owner.UID),
		RestoreNameLabel:      dataDownload.Identity.Metadata.Labels["velero.io/restore-name"],
		RestoreUIDLabelSHA256: restoreproof.SHA256(dataDownload.Identity.Metadata.Labels["velero.io/restore-uid"]),
		TerminalStatus:        dataDownload.Status.Phase,
		StartedAt:             dataDownload.Status.StartTimestamp,
		CompletedAt:           dataDownload.Status.CompletionTimestamp,
		BytesDone:             dataDownload.Status.Progress.BytesDone,
		TotalBytes:            dataDownload.Status.Progress.TotalBytes,
		OperationIDSHA256:     restoreproof.SHA256(operationID),
		TargetPVC:             targetPointer(targetPVC.Identity.Target("persistentvolumeclaims")),
		SourcePVC:             sourcePointer(source),
		EvidenceRef:           request.EvidencePrefix + "/velero-data-download",
	}
	helper.DataDownload = &restoreproof.DataDownloadLineage{
		TargetVolumePVC:               dataDownload.Spec.TargetVolume.PVC,
		TargetVolumePV:                dataDownload.Spec.TargetVolume.PV,
		TargetVolumeNamespace:         dataDownload.Spec.TargetVolume.Namespace,
		TargetPV:                      targetPointer(targetPV.Identity.Target("persistentvolumes")),
		BackupStorageLocation:         dataDownload.Spec.BackupStorageLocation,
		DataMover:                     dataDownload.Spec.DataMover,
		SnapshotIDSHA256:              restoreproof.SHA256(dataDownload.Spec.SnapshotID),
		SourceNamespace:               dataDownload.Spec.SourceNamespace,
		DataMoverConfigSHA256:         optionalMapSHA256(dataDownload.Spec.DataMoverConfig),
		Cancel:                        dataDownload.Spec.Cancel,
		OperationTimeout:              dataDownload.Spec.OperationTimeout,
		NodeOS:                        dataDownload.Spec.NodeOS,
		SnapshotSize:                  dataDownload.Spec.SnapshotSize,
		AsyncOperationIDLabelSHA256:   restoreproof.SHA256(operationID),
		DataUploadResultObject:        result.Object,
		DataUploadUIDSHA256:           upload.UIDSHA256,
		ArchivedDataUploadSHA256:      upload.ArchivedObjectSHA256,
		DataUploadResultPayloadSHA256: result.ResultPayloadSHA256,
	}
	helper.EvidenceSHA256 = restoreproof.DataDownloadEvidenceSHA256(&helper)
	return helper
}

func listAll(ctx context.Context, reader KubernetesReader, gvr restoreproof.GVR, namespace, selector, apiVersion, kind string) ([][]byte, error) {
	const (
		limit                 = 200
		maximumPages          = 128
		maximumItems          = 4096
		maximumAggregateBytes = 16 << 20
	)
	itemKind := strings.TrimSuffix(kind, "List")
	if itemKind == kind || itemKind == "" {
		return nil, errors.New("Kubernetes list kind is invalid")
	}
	continueToken := ""
	resourceVersion := ""
	seenTokens := map[string]bool{}
	seenObjects := map[string]string{}
	previousIdentity := ""
	aggregateBytes := 0
	var items [][]byte
	for pageNumber := 0; pageNumber < maximumPages; pageNumber++ {
		payload, err := reader.ListPage(ctx, gvr, namespace, selector, continueToken, limit)
		if err != nil {
			return nil, err
		}
		aggregateBytes += len(payload)
		if aggregateBytes > maximumAggregateBytes {
			zeroBytes(payload)
			return nil, errors.New("Kubernetes list aggregate exceeded limit")
		}
		page, err := DecodeListPage(payload, apiVersion, kind)
		zeroBytes(payload)
		if err != nil {
			return nil, err
		}
		if resourceVersion == "" {
			resourceVersion = page.ResourceVersion
		} else if page.ResourceVersion != resourceVersion {
			return nil, errors.New("Kubernetes list resourceVersion drifted across pages")
		}
		for _, raw := range page.Items {
			var envelope objectEnvelope
			if err := strictjson.Decode(raw, &envelope); err != nil || envelope.APIVersion != apiVersion || envelope.Kind != itemKind || envelope.Metadata.Namespace != namespace {
				return nil, errors.New("decode Kubernetes list identity")
			}
			identity := envelope.Metadata.Namespace + "\x00" + envelope.Metadata.Name
			if previousIdentity != "" && identity <= previousIdentity {
				return nil, errors.New("Kubernetes list ordering or object identity changed across pages")
			}
			if previousUID, exists := seenObjects[identity]; exists && previousUID != envelope.Metadata.UID {
				return nil, errors.New("Kubernetes list object was replaced across pages")
			} else if exists {
				return nil, errors.New("Kubernetes list object identity is duplicated")
			}
			if len(items) >= maximumItems {
				return nil, errors.New("Kubernetes list aggregate exceeded limit")
			}
			seenObjects[identity] = envelope.Metadata.UID
			previousIdentity = identity
			items = append(items, raw)
		}
		if page.Continue == "" {
			sort.Slice(items, func(left, right int) bool { return string(items[left]) < string(items[right]) })
			return items, nil
		}
		if page.Continue == continueToken || seenTokens[page.Continue] {
			return nil, errors.New("Kubernetes list continuation token repeated")
		}
		seenTokens[page.Continue] = true
		continueToken = page.Continue
	}
	return nil, errors.New("Kubernetes list did not terminate")
}

func validateRequest(request CollectionRequest) error {
	if request.SchemaVersion != CollectionRequestSchemaVersion || !safeName(request.VeleroNamespace) || !safeName(request.RestoreName) ||
		!safeName(request.SourceNamespace) || !safeName(request.SourcePVC) || !safeName(request.TargetNamespace) || !safeName(request.TargetPVC) ||
		!safeName(request.DataUploadName) || !safeName(request.ServerStatusRequestName) || !validSHA256(request.ServerStatusRequestUIDSHA256) ||
		!validSHA256(request.CleanupRunNonceSHA256) ||
		request.SourceNamespace == request.TargetNamespace || request.SourcePVC != request.TargetPVC || !safeEvidencePrefix(request.EvidencePrefix) || request.DataUploadResultObservation == nil {
		return errors.New("restore proof collection request is invalid")
	}
	return nil
}

func validateBaselineRequest(request BaselineRequest) error {
	if request.SchemaVersion != BaselineRequestSchemaVersion || !safeName(request.SourceNamespace) || !safeName(request.SourcePVC) || !safeEvidencePrefix(request.EvidencePrefix) {
		return errors.New("restore proof baseline request is invalid")
	}
	return nil
}

func validateBaseline(request CollectionRequest, baseline restoreproof.SourceBaseline) error {
	if baseline.SchemaVersion != restoreproof.BaselineSchemaVersion || !canonicalTime(baseline.CapturedAt) || baseline.Source.Resource != "persistentvolumeclaims" ||
		baseline.Source.Namespace != request.SourceNamespace || baseline.Source.Name != request.SourcePVC || baseline.Source.UIDSHA256 == "" ||
		baseline.Source.ResourceVersionBeforeSHA256 != baseline.Source.ResourceVersionAfterSHA256 || baseline.Source.StateBeforeSHA256 != baseline.Source.StateAfterSHA256 ||
		baseline.EvidenceRef != request.EvidencePrefix+"/source-pvc-baseline" {
		return errors.New("source PVC baseline is invalid")
	}
	want := restoreproof.SourceBaselineEvidenceSHA256(baseline)
	if baseline.EvidenceSHA256 != want {
		return errors.New("source PVC baseline digest is invalid")
	}
	return nil
}

func validateBaselineTimeline(baseline restoreproof.SourceBaseline, restoreObject Restore) error {
	capturedAt, capturedErr := time.Parse(time.RFC3339Nano, baseline.CapturedAt)
	restoreStarted, restoreErr := time.Parse(time.RFC3339Nano, restoreObject.Status.StartTimestamp)
	if capturedErr != nil || restoreErr != nil || !capturedAt.Before(restoreStarted) || restoreStarted.Sub(capturedAt) > sourceBaselineMaximumAge {
		return errors.New("source PVC baseline was not captured immediately before the restore")
	}
	return nil
}

func validatePreCleanupTimeline(restoreObject Restore, probe ProbeObservation, presence BackendObservation, ready CleanupReady) error {
	restoreCompleted, restoreErr := time.Parse(time.RFC3339Nano, restoreObject.Status.CompletionTimestamp)
	probeStarted, probeStartErr := time.Parse(time.RFC3339Nano, probe.StartedAt)
	probeCompleted, probeCompleteErr := time.Parse(time.RFC3339Nano, probe.CompletedAt)
	presenceObserved, presenceErr := time.Parse(time.RFC3339Nano, presence.ObservedAt)
	readyAt, readyErr := time.Parse(time.RFC3339Nano, ready.ReadyAt)
	probeDuration := probeCompleted.Sub(probeStarted)
	if restoreErr != nil || probeStartErr != nil || probeCompleteErr != nil || presenceErr != nil || readyErr != nil ||
		probeStarted.Before(restoreCompleted) || !probeStarted.Before(probeCompleted) || probeDuration <= 0 ||
		probeCompleted.After(readyAt) || presenceObserved.Before(probeCompleted) || presenceObserved.After(readyAt) {
		return errors.New("pre-cleanup validation timeline is invalid")
	}
	return nil
}

func validProbeObservation(observation ProbeObservation) bool {
	if observation.SchemaVersion != AdapterResponseSchemaVersion || !validRuntimeID(observation.Implementation) || !validAdapterVersion(observation.Version) ||
		!validSHA256(observation.RequestSHA256) || !validSHA256(observation.AdapterExecutableSHA256) || observation.HashAlgorithm != "sha256" ||
		observation.SourceSHA256 == "" || observation.SourceSHA256 != observation.TargetSHA256 || observation.ValidatedBytes <= 0 ||
		!canonicalTime(observation.StartedAt) || !canonicalTime(observation.CompletedAt) || !timestampAfter(observation.StartedAt, observation.CompletedAt) ||
		!validRuntimeID(observation.EvidenceRef) || !validSHA256(observation.EvidenceSHA256) || !validSHA256(observation.SourceSHA256) {
		return false
	}
	return true
}

func validBackendObservation(observation BackendObservation) bool {
	return observation.SchemaVersion == AdapterResponseSchemaVersion && validRuntimeID(observation.Implementation) && validAdapterVersion(observation.Version) &&
		observation.Present != nil && validSHA256(observation.RequestSHA256) && validSHA256(observation.AdapterExecutableSHA256) &&
		validSHA256(observation.ArtifactHandleSHA256) && canonicalTime(observation.ObservedAt) &&
		validRuntimeID(observation.EvidenceRef) && validSHA256(observation.EvidenceSHA256)
}

func newChallenge() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func adapterRequestSHA256(request any) string {
	return AdapterRequestSHA256(request)
}

func requestJSONSHA256(request any) string {
	payload, err := json.Marshal(request)
	if err != nil {
		return ""
	}
	return restoreproof.SHA256(string(payload))
}

func timestampWithin(value string, lower, upper time.Time, tolerance time.Duration) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return false
	}
	return !parsed.Before(lower.Add(-tolerance)) && !parsed.After(upper.Add(tolerance))
}

func durationMillisecondsCeiling(duration time.Duration) int64 {
	if duration <= 0 {
		return 0
	}
	milliseconds := duration / time.Millisecond
	if duration%time.Millisecond != 0 {
		milliseconds++
	}
	return int64(milliseconds)
}

func controllerOwner(owners []OwnerReference, apiVersion, kind, name string) (OwnerReference, bool) {
	var match OwnerReference
	count := 0
	for _, owner := range owners {
		if owner.APIVersion == apiVersion && owner.Kind == kind && owner.Name == name && owner.Controller != nil && *owner.Controller {
			match = owner
			count++
		}
	}
	return match, count == 1
}

func sameDataUpload(left, right DataUpload) bool {
	return left.Identity.Metadata.Name == right.Identity.Metadata.Name && left.Identity.Metadata.Namespace == right.Identity.Metadata.Namespace &&
		left.Identity.Metadata.UID == right.Identity.Metadata.UID && left.Identity.Metadata.ResourceVersion == right.Identity.Metadata.ResourceVersion &&
		left.Identity.StateSHA256 == right.Identity.StateSHA256 && reflect.DeepEqual(left.Spec, right.Spec) && reflect.DeepEqual(left.Status, right.Status)
}

func targetProofs(targets []observedTarget) []restoreproof.TargetResource {
	result := make([]restoreproof.TargetResource, 0, len(targets))
	for _, target := range targets {
		result = append(result, target.Proof)
	}
	return result
}

func sourcePointer(value restoreproof.SourceResource) *restoreproof.SourceResource { return &value }
func targetPointer(value restoreproof.TargetResource) *restoreproof.TargetResource { return &value }
func sourceResourceFromIdentity(identity Identity, resource string) restoreproof.SourceResource {
	uidSHA256 := restoreproof.SHA256(identity.Metadata.UID)
	resourceVersionSHA256 := restoreproof.SHA256(identity.Metadata.ResourceVersion)
	return restoreproof.SourceResource{
		Resource: resource, Namespace: identity.Metadata.Namespace, Name: identity.Metadata.Name, UIDSHA256: uidSHA256,
		ResourceVersionBeforeSHA256: resourceVersionSHA256, ResourceVersionAfterSHA256: resourceVersionSHA256,
		StateBeforeSHA256: identity.ProofStateSHA256, StateAfterSHA256: identity.ProofStateSHA256,
	}
}
func cloneStringMap(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func optionalMapSHA256(value map[string]string) string {
	if len(value) == 0 {
		return ""
	}
	payload, _ := json.Marshal(value)
	return restoreproof.SHA256(string(payload))
}

func optionalValueSHA256(value string) string {
	if value == "" {
		return ""
	}
	return restoreproof.SHA256(value)
}

func canonicalJSONSHA256(value []byte) string {
	var decoded any
	if err := strictjson.Decode(value, &decoded); err != nil {
		return ""
	}
	payload, err := json.Marshal(decoded)
	if err != nil {
		return ""
	}
	return restoreproof.SHA256(string(payload))
}

func sameStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func validBackupUploaderConfig(config *UploaderConfigForBackup) bool {
	return config == nil || config.ParallelFilesUpload >= 0
}

func validRestoreUploaderConfig(config *UploaderConfigForRestore) bool {
	return config == nil || config.ParallelFilesDownload >= 0
}

func expectedBackupUploaderConfig(config *UploaderConfigForBackup) map[string]string {
	if config == nil || config.ParallelFilesUpload <= 0 {
		return nil
	}
	return map[string]string{"ParallelFilesUpload": strconv.Itoa(config.ParallelFilesUpload)}
}

func expectedRestoreUploaderConfig(config *UploaderConfigForRestore) map[string]string {
	if config == nil {
		return nil
	}
	writeSparse := false
	if config.WriteSparseFiles != nil {
		writeSparse = *config.WriteSparseFiles
	}
	result := map[string]string{"WriteSparseFiles": strconv.FormatBool(writeSparse)}
	if config.ParallelFilesDownload > 0 {
		result["ParallelFilesDownload"] = strconv.Itoa(config.ParallelFilesDownload)
	}
	return result
}

func builtInDataMover(value string) bool        { return value == "" || value == "velero" }
func canonicalTimestamp(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
func canonicalTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.UTC().Format(time.RFC3339Nano) == value
}
func timestampAfter(left, right string) bool {
	l, leftErr := time.Parse(time.RFC3339Nano, left)
	r, rightErr := time.Parse(time.RFC3339Nano, right)
	return leftErr == nil && rightErr == nil && r.After(l)
}
func timestampAtLeast(left, right string, interval time.Duration) bool {
	l, leftErr := time.Parse(time.RFC3339Nano, left)
	r, rightErr := time.Parse(time.RFC3339Nano, right)
	return leftErr == nil && rightErr == nil && r.Sub(l) >= interval
}

func timestampTooFarInFuture(value string, now time.Time, tolerance time.Duration) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err != nil || parsed.After(now.Add(tolerance))
}

func maxCanonicalTimestamp(now time.Time, other string) string {
	parsed, err := time.Parse(time.RFC3339Nano, other)
	if err == nil && parsed.After(now) {
		return canonicalTimestamp(parsed)
	}
	return canonicalTimestamp(now)
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func validAdapterVersion(value string) bool {
	if len(value) < 2 || len(value) > 255 || value[0] != 'v' {
		return false
	}
	for _, character := range value[1:] {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._:+/-", character)) {
			return false
		}
	}
	return true
}

func validRuntimeID(value string) bool {
	if value == "" || len(value) > 255 || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for _, character := range value[1:] {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._:+/-", character)) {
			return false
		}
	}
	return true
}

func veleroValidLabelName(value string) string {
	if len(value) <= 63 {
		return value
	}
	digest := sha256.Sum256([]byte(value))
	return value[:57] + hex.EncodeToString(digest[:])[:6]
}

func safeName(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, " /\\\t\r\n") {
		return false
	}
	if !asciiLowerOrDigit(value[0]) || !asciiLowerOrDigit(value[len(value)-1]) {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '.') {
			return false
		}
	}
	return true
}

func asciiLowerOrDigit(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func safeEvidencePrefix(value string) bool {
	if value == "" || len(value) > 229 || !asciiAlphaNumeric(value[0]) || !asciiAlphaNumeric(value[len(value)-1]) || strings.Contains(value, "..") {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("-._/+:", character)) {
			return false
		}
	}
	return true
}
