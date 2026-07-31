// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package restoreproof

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	providerAbsenceMinimumInterval = 10 * time.Second
	sourceBaselineMaximumAge       = 15 * time.Minute
	serverStatusFreshness          = time.Minute
	serverStatusAllowedFutureSkew  = 30 * time.Second
)

var (
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	namePattern   = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,254}$`)
)

// ValidateCSIDataMoverVolumeReceipt validates the complete reusable receipt.
func ValidateCSIDataMoverVolumeReceipt(receipt *VolumeReceipt) error {
	if receipt == nil || receipt.SchemaVersion != ReceiptSchemaVersion || receipt.ProofScope != ScopeSingleVolumeDataPath ||
		receipt.VeleroVersion != VeleroVersion || !canonicalTime(receipt.CollectedAt) {
		return errors.New("restore proof envelope is invalid")
	}
	if err := validateContext(&receipt.Context); err != nil {
		return err
	}
	if err := validateVeleroRuntime(receipt); err != nil {
		return err
	}
	if err := ValidateCSIDataMoverVolumeLineage(receipt.Context, &receipt.Lineage); err != nil {
		return err
	}
	if err := validateDataUploadBindings(receipt); err != nil {
		return err
	}
	collected, _ := time.Parse(time.RFC3339Nano, receipt.CollectedAt)
	verified, _ := time.Parse(time.RFC3339Nano, receipt.Context.Cleanup.VerifiedAt)
	if collected.Before(verified) {
		return errors.New("restore proof was collected before cleanup verification")
	}
	if !validDigest(receipt.ReceiptSHA256) || receipt.ReceiptSHA256 != ReceiptSHA256(*receipt) {
		return errors.New("restore proof receipt digest is invalid")
	}
	return nil
}

func validateVeleroRuntime(receipt *VolumeReceipt) error {
	runtime := &receipt.VeleroRuntime
	if runtime.GVR != VeleroV1ServerStatusRequestGVR || runtime.Object == nil || runtime.Object.Resource != "serverstatusrequests.velero.io" ||
		!validName(runtime.Object.Namespace) || runtime.Object.Namespace != receipt.Context.VeleroNamespace || !validName(runtime.Object.Name) || !validDigest(runtime.Object.UIDSHA256) ||
		!validDigest(runtime.Object.ResourceVersionSHA256) || !validDigest(runtime.Object.ValidatedStateSHA256) || runtime.ServerVersion != VeleroVersion ||
		runtime.ServerVersion != receipt.VeleroVersion || runtime.Phase != "Processed" || !canonicalTime(runtime.ProcessedAt) || !canonicalTime(runtime.ObservedAt) ||
		!validEvidence(runtime.EvidenceRef, runtime.EvidenceSHA256) || runtime.EvidenceSHA256 != VeleroRuntimeEvidenceSHA256(*runtime) {
		return errors.New("Velero runtime attestation is invalid")
	}
	processed, _ := time.Parse(time.RFC3339Nano, runtime.ProcessedAt)
	observed, _ := time.Parse(time.RFC3339Nano, runtime.ObservedAt)
	restoreCompleted, _ := time.Parse(time.RFC3339Nano, receipt.Context.CompletedAt)
	cleanupStarted, _ := time.Parse(time.RFC3339Nano, receipt.Context.Cleanup.CleanupStartedAt)
	collected, _ := time.Parse(time.RFC3339Nano, receipt.CollectedAt)
	if !processed.After(restoreCompleted) || observed.Before(processed.Add(-serverStatusAllowedFutureSkew)) || observed.After(processed.Add(serverStatusFreshness)) ||
		observed.After(cleanupStarted) || observed.After(collected) {
		return errors.New("Velero runtime attestation timeline is invalid")
	}
	return nil
}

// ValidateCSIDataMoverVolumeLineage validates the method-specific lineage and
// can be called by downstream signed-bundle validators.
func ValidateCSIDataMoverVolumeLineage(context VolumeRestoreContext, lineage *DataLineage) error {
	if err := validateContext(&context); err != nil {
		return err
	}
	if lineage == nil || lineage.Status != "verified" || lineage.Method != MethodCSIDataMover || lineage.ValidatedBytes <= 0 ||
		!validDigest(lineage.ProbeSetSHA256) || !validDigest(lineage.AggregateDataSHA256) || !validDigest(lineage.ProviderAbsenceSetSHA256) ||
		!validEvidence(lineage.EvidenceRef, lineage.EvidenceSHA256) || lineage.EvidenceSHA256 != DataLineageEvidenceSHA256(lineage) {
		return errors.New("typed restore data lineage is missing or invalid")
	}
	probesByTarget, total, err := validateProbes(context, lineage.Probes)
	if err != nil {
		return err
	}
	if total != lineage.ValidatedBytes || lineage.ProbeSetSHA256 != ProbeSetSHA256(lineage.Probes) || lineage.AggregateDataSHA256 != AggregateDataSHA256(lineage.Probes) {
		return errors.New("typed restore data probe set digest or byte total is invalid")
	}
	if err := validateHelpers(context, probesByTarget, lineage.Helpers); err != nil {
		return err
	}
	if err := validateBackends(context, lineage.Probes, lineage.BackendArtifacts); err != nil {
		return err
	}
	if lineage.ProviderAbsenceSetSHA256 != ProviderAbsenceSetSHA256(lineage.BackendArtifacts) {
		return errors.New("typed provider final absence set digest is invalid")
	}
	return nil
}

func validateContext(context *VolumeRestoreContext) error {
	if context == nil || !validName(context.VeleroNamespace) || !validName(context.RestoreID) || !validName(context.BackupID) || !validName(context.BackupStorageLocation) ||
		!validDigest(context.RestoreUIDSHA256) || !validDigest(context.RestoreResourceVersionSHA256) ||
		!validDigest(context.BackupUIDSHA256) || !validDigest(context.BackupResourceVersionSHA256) ||
		len(context.NamespaceMapping) != 1 || !canonicalTime(context.BackupCompletedAt) || !canonicalTime(context.RestoreStartedAt) || !canonicalTime(context.CompletedAt) {
		return errors.New("restore proof parent context is invalid")
	}
	started, _ := time.Parse(time.RFC3339Nano, context.RestoreStartedAt)
	completed, _ := time.Parse(time.RFC3339Nano, context.CompletedAt)
	backupCompleted, _ := time.Parse(time.RFC3339Nano, context.BackupCompletedAt)
	timeout, timeoutErr := time.ParseDuration(context.CSISnapshotTimeout)
	if backupCompleted.After(started) || !started.Before(completed) || timeoutErr != nil || timeout <= 0 ||
		context.BackupUploaderConfigSHA256 != "" && !validDigest(context.BackupUploaderConfigSHA256) ||
		context.RestoreUploaderConfigSHA256 != "" && !validDigest(context.RestoreUploaderConfigSHA256) ||
		context.DataMoverConfigSHA256 != context.RestoreUploaderConfigSHA256 {
		return errors.New("restore proof parent timeline is invalid")
	}
	baseline := &context.SourceBaseline
	if baseline.SchemaVersion != BaselineSchemaVersion || !canonicalTime(baseline.CapturedAt) || baseline.Source.Resource != "persistentvolumeclaims" ||
		!validName(baseline.Source.Namespace) || !validName(baseline.Source.Name) || !validDigest(baseline.Source.UIDSHA256) ||
		!validDigest(baseline.Source.ResourceVersionBeforeSHA256) || baseline.Source.ResourceVersionBeforeSHA256 != baseline.Source.ResourceVersionAfterSHA256 ||
		!validDigest(baseline.Source.StateBeforeSHA256) || baseline.Source.StateBeforeSHA256 != baseline.Source.StateAfterSHA256 ||
		!validEvidence(baseline.EvidenceRef, baseline.EvidenceSHA256) || baseline.EvidenceSHA256 != SourceBaselineEvidenceSHA256(*baseline) {
		return errors.New("restore proof source baseline is invalid")
	}
	baselineCaptured, _ := time.Parse(time.RFC3339Nano, baseline.CapturedAt)
	if !baselineCaptured.Before(started) || started.Sub(baselineCaptured) > sourceBaselineMaximumAge {
		return errors.New("restore proof source baseline timeline is invalid")
	}
	for source, target := range context.NamespaceMapping {
		if !validName(source) || !validName(target) || source == target {
			return errors.New("restore proof namespace mapping is invalid")
		}
	}
	cleanup := &context.Cleanup
	if !canonicalTime(cleanup.ValidationCompletedAt) || !canonicalTime(cleanup.CleanupStartedAt) || !canonicalTime(cleanup.CleanupCompletedAt) || !canonicalTime(cleanup.VerifiedAt) ||
		len(cleanup.SourceResources) != 2 || len(cleanup.TargetResources) != 4 || len(cleanup.VeleroAutoCleanedResources) != 1 {
		return errors.New("restore proof cleanup context is invalid")
	}
	validation, _ := time.Parse(time.RFC3339Nano, cleanup.ValidationCompletedAt)
	cleanupStarted, _ := time.Parse(time.RFC3339Nano, cleanup.CleanupStartedAt)
	cleanupCompleted, _ := time.Parse(time.RFC3339Nano, cleanup.CleanupCompletedAt)
	verified, _ := time.Parse(time.RFC3339Nano, cleanup.VerifiedAt)
	if validation.After(cleanupStarted) || cleanupStarted.After(cleanupCompleted) || cleanupCompleted.After(verified) {
		return errors.New("restore proof cleanup timeline is invalid")
	}
	if validation.Before(completed) {
		return errors.New("restore proof validation predates restore completion")
	}
	expectedSources := map[string]int{"persistentvolumeclaims": 1, "persistentvolumes": 1}
	seenSource := map[string]bool{}
	baselineFound := false
	previousSourceIdentity := ""
	for index := range cleanup.SourceResources {
		resource := cleanup.SourceResources[index]
		identity := objectIdentity(resource.Resource, resource.Namespace, resource.Name)
		if expectedSources[resource.Resource] == 0 || previousSourceIdentity != "" && identity <= previousSourceIdentity || !validName(resource.Name) || resource.Resource == "persistentvolumeclaims" && !validName(resource.Namespace) ||
			resource.Resource == "persistentvolumes" && resource.Namespace != "" || seenSource[identity] ||
			!validDigest(resource.UIDSHA256) || !validDigest(resource.ResourceVersionBeforeSHA256) || !validDigest(resource.ResourceVersionAfterSHA256) ||
			!validDigest(resource.StateBeforeSHA256) || resource.StateBeforeSHA256 != resource.StateAfterSHA256 {
			return errors.New("restore proof source inventory is invalid")
		}
		expectedSources[resource.Resource]--
		seenSource[identity] = true
		previousSourceIdentity = identity
		if resource.Resource == "persistentvolumeclaims" && sourceMatchesBaseline(resource, baseline.Source) {
			baselineFound = true
		}
	}
	if !baselineFound || expectedSources["persistentvolumeclaims"] != 0 || expectedSources["persistentvolumes"] != 0 {
		return errors.New("restore proof source inventory is not bound to its baseline")
	}
	expectedTargets := map[string]int{"persistentvolumeclaims": 1, "persistentvolumes": 1, "datadownloads.velero.io": 1, "configmaps": 1}
	seenTargets := map[string]bool{}
	previousTargetIdentity := ""
	for index := range cleanup.TargetResources {
		resource := cleanup.TargetResources[index]
		identity := objectIdentity(resource.Resource, resource.Namespace, resource.Name)
		if expectedTargets[resource.Resource] == 0 || previousTargetIdentity != "" && identity <= previousTargetIdentity || !validName(resource.Name) || resource.Resource != "persistentvolumes" && !validName(resource.Namespace) ||
			resource.Resource == "persistentvolumes" && resource.Namespace != "" || seenTargets[identity] || !validDigest(resource.UIDSHA256) ||
			!validDigest(resource.ResourceVersionSHA256) || !validDigest(resource.ValidatedStateSHA256) {
			return errors.New("restore proof target inventory is invalid")
		}
		expectedTargets[resource.Resource]--
		seenTargets[identity] = true
		previousTargetIdentity = identity
	}
	for _, remaining := range expectedTargets {
		if remaining != 0 {
			return errors.New("restore proof target inventory is incomplete")
		}
	}
	autoCleaned := cleanup.VeleroAutoCleanedResources[0]
	if autoCleaned.Resource != "configmaps" || !containsTarget(cleanup.TargetResources, &autoCleaned) {
		return errors.New("restore proof Velero auto-cleaned inventory is invalid")
	}
	return nil
}

func sourceMatchesBaseline(resource, baseline SourceResource) bool {
	return resource.Resource == baseline.Resource && resource.Namespace == baseline.Namespace && resource.Name == baseline.Name &&
		resource.UIDSHA256 == baseline.UIDSHA256 && resource.ResourceVersionBeforeSHA256 == baseline.ResourceVersionBeforeSHA256 &&
		resource.StateBeforeSHA256 == baseline.StateBeforeSHA256 && resource.StateAfterSHA256 == baseline.StateAfterSHA256
}

func validateProbes(context VolumeRestoreContext, probes []DataProbe) (map[string]DataProbe, int64, error) {
	sources := sourceInventory(context.Cleanup.SourceResources, "persistentvolumeclaims")
	targetPVCs := targetInventory(context.Cleanup.TargetResources, "persistentvolumeclaims")
	targetPVs := targetInventory(context.Cleanup.TargetResources, "persistentvolumes")
	if len(sources) == 0 || len(probes) != len(sources) || len(targetPVCs) != len(sources) || len(targetPVs) != len(sources) {
		return nil, 0, errors.New("typed restore data probes must cover every exact source PVC, restored PVC, and restored PV")
	}
	byTarget := make(map[string]DataProbe, len(probes))
	seenSource := map[string]bool{}
	seenPV := map[string]bool{}
	previous := ""
	var total int64
	for index := range probes {
		probe := probes[index]
		if err := validateProbe(context, probe); err != nil {
			return nil, 0, err
		}
		identity := sourceIdentity(probe.Source) + "\x00" + targetIdentity(probe.Target) + "\x00" + targetIdentity(probe.TargetPV)
		if previous != "" && identity <= previous || seenSource[sourceIdentity(probe.Source)] || byTarget[targetIdentity(probe.Target)].Status != "" || seenPV[targetIdentity(probe.TargetPV)] {
			return nil, 0, errors.New("typed restore data probes must be unique and canonically ordered")
		}
		previous = identity
		seenSource[sourceIdentity(probe.Source)] = true
		seenPV[targetIdentity(probe.TargetPV)] = true
		byTarget[targetIdentity(probe.Target)] = probe
		if probe.ValidatedBytes > (1<<63-1)-total {
			return nil, 0, errors.New("typed restore data probe byte total overflowed")
		}
		total += probe.ValidatedBytes
	}
	if len(seenSource) != len(sources) || len(byTarget) != len(targetPVCs) || len(seenPV) != len(targetPVs) {
		return nil, 0, errors.New("typed restore data probe coverage is incomplete")
	}
	return byTarget, total, nil
}

func validateProbe(context VolumeRestoreContext, probe DataProbe) error {
	if probe.Status != "verified" || !validRuntimeID(probe.Implementation) || !validVersion(probe.Version) || probe.HashAlgorithm != "sha256" ||
		!validDigest(probe.RequestSHA256) || !validDigest(probe.AdapterExecutableSHA256) ||
		!validDigest(probe.SourceDataSHA256) || probe.SourceDataSHA256 != probe.RestoredDataSHA256 || probe.ValidatedBytes <= 0 ||
		!validEvidence(probe.EvidenceRef, probe.EvidenceSHA256) || probe.SourceGVR != CoreV1PVCGVR || probe.TargetGVR != CoreV1PVCGVR ||
		probe.Source == nil || probe.Target == nil || probe.TargetPV == nil || !validName(probe.SourcePVCVolumeName) {
		return errors.New("typed restore data probe metadata or checksum is invalid")
	}
	if !containsSource(context.Cleanup.SourceResources, probe.Source) || !containsTarget(context.Cleanup.TargetResources, probe.Target) || !containsTarget(context.Cleanup.TargetResources, probe.TargetPV) ||
		probe.Source.Resource != "persistentvolumeclaims" || probe.Target.Resource != "persistentvolumeclaims" || probe.TargetPV.Resource != "persistentvolumes" || probe.TargetPV.Namespace != "" ||
		probe.TargetPVCVolumeName != probe.TargetPV.Name || context.NamespaceMapping[probe.Source.Namespace] != probe.Target.Namespace || probe.Source.Name != probe.Target.Name ||
		probe.Source.UIDSHA256 == probe.Target.UIDSHA256 || probe.Source.StateBeforeSHA256 != probe.Source.StateAfterSHA256 {
		return errors.New("typed restore data probe source and target lineage is invalid")
	}
	started, startErr := time.Parse(time.RFC3339Nano, probe.StartedAt)
	completed, completeErr := time.Parse(time.RFC3339Nano, probe.CompletedAt)
	restoreCompleted, restoreErr := time.Parse(time.RFC3339Nano, context.CompletedAt)
	validationCompleted, validationErr := time.Parse(time.RFC3339Nano, context.Cleanup.ValidationCompletedAt)
	if startErr != nil || completeErr != nil || restoreErr != nil || validationErr != nil || started.Before(restoreCompleted) || !started.Before(completed) || completed.After(validationCompleted) ||
		probe.ObservedDurationMilliseconds != durationMillisecondsCeiling(completed.Sub(started)) {
		return errors.New("typed restore data probe timeline is invalid")
	}
	return nil
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

func validateHelpers(context VolumeRestoreContext, probes map[string]DataProbe, helpers []AsyncHelper) error {
	expected := targetInventory(context.Cleanup.TargetResources, "datadownloads.velero.io")
	if len(expected) == 0 || len(helpers) != len(expected) || len(helpers) != len(probes) {
		return errors.New("CSI data-mover restore requires the exact signed DataDownload set")
	}
	previous := ""
	seenOperations := map[string]bool{}
	covered := map[string]bool{}
	for index := range helpers {
		helper := helpers[index]
		probe, linked := probes[targetIdentity(helper.TargetPVC)]
		identity := targetIdentity(helper.Object)
		if helper.GVR != DataDownloadGVR || helper.Object == nil || helper.Object.Resource != "datadownloads.velero.io" || !containsTarget(context.Cleanup.TargetResources, helper.Object) ||
			helper.Object.Namespace != context.VeleroNamespace ||
			helper.RestoreUIDSHA256 != context.RestoreUIDSHA256 || helper.OwnerRestoreUIDSHA256 != context.RestoreUIDSHA256 || helper.RestoreNameLabel != validLabelValue(context.RestoreID) ||
			helper.RestoreUIDLabelSHA256 != context.RestoreUIDSHA256 || helper.TerminalStatus != "Completed" || helper.BytesDone <= 0 || helper.BytesDone != helper.TotalBytes ||
			!linked || helper.TargetPVC == nil || helper.SourcePVC == nil || *helper.SourcePVC != *probe.Source || !containsTarget(context.Cleanup.TargetResources, helper.TargetPVC) ||
			!containsSource(context.Cleanup.SourceResources, helper.SourcePVC) || !validDigest(helper.OperationIDSHA256) || seenOperations[helper.OperationIDSHA256] ||
			!validEvidence(helper.EvidenceRef, helper.EvidenceSHA256) || helper.EvidenceSHA256 != DataDownloadEvidenceSHA256(&helper) ||
			previous != "" && identity <= previous || expected[identity].Name == "" {
			return errors.New("typed DataDownload helper identity, terminal progress, operation, or PVC linkage is invalid")
		}
		if err := validateDataDownload(context, probe, helper); err != nil {
			return err
		}
		started, startErr := time.Parse(time.RFC3339Nano, helper.StartedAt)
		completed, completeErr := time.Parse(time.RFC3339Nano, helper.CompletedAt)
		restoreStarted, _ := time.Parse(time.RFC3339Nano, context.RestoreStartedAt)
		restoreCompleted, _ := time.Parse(time.RFC3339Nano, context.CompletedAt)
		if startErr != nil || completeErr != nil || started.Before(restoreStarted) || !started.Before(completed) || completed.After(restoreCompleted) {
			return errors.New("typed DataDownload helper timeline is invalid")
		}
		previous = identity
		seenOperations[helper.OperationIDSHA256] = true
		covered[targetIdentity(helper.TargetPVC)] = true
	}
	if len(covered) != len(probes) {
		return errors.New("typed DataDownload helper set does not cover every restored PVC")
	}
	return nil
}

func validateDataDownload(context VolumeRestoreContext, probe DataProbe, helper AsyncHelper) error {
	data := helper.DataDownload
	if data == nil || data.TargetVolumePVC != helper.TargetPVC.Name || data.TargetVolumePV != "" || data.TargetVolumeNamespace != helper.TargetPVC.Namespace ||
		data.TargetPV == nil || *data.TargetPV != *probe.TargetPV || !containsTarget(context.Cleanup.TargetResources, data.TargetPV) || data.BackupStorageLocation != context.BackupStorageLocation ||
		!builtInDataMover(data.DataMover) || !validDigest(data.SnapshotIDSHA256) || data.SourceNamespace != helper.SourcePVC.Namespace ||
		context.NamespaceMapping[data.SourceNamespace] != helper.TargetPVC.Namespace || data.DataMoverConfigSHA256 != context.RestoreUploaderConfigSHA256 ||
		data.OperationTimeout != context.CSISnapshotTimeout || data.Cancel || data.NodeOS != "linux" ||
		data.SnapshotSize != helper.TotalBytes || data.AsyncOperationIDLabelSHA256 != helper.OperationIDSHA256 || data.DataUploadResultObject == nil ||
		data.DataUploadResultObject.Resource != "configmaps" || !containsTarget(context.Cleanup.TargetResources, data.DataUploadResultObject) ||
		!validDigest(data.DataUploadUIDSHA256) || !validDigest(data.ArchivedDataUploadSHA256) || !validDigest(data.DataUploadResultPayloadSHA256) {
		return errors.New("DataDownload typed spec, labels, or DataUploadResult linkage is invalid")
	}
	duration, err := time.ParseDuration(data.OperationTimeout)
	if err != nil || duration <= 0 {
		return errors.New("DataDownload operation timeout is invalid")
	}
	return nil
}

func validateBackends(context VolumeRestoreContext, probes []DataProbe, backends []BackendArtifactLineage) error {
	if len(backends) != len(probes) {
		return errors.New("typed provider backend lineage must cover every restored PV")
	}
	probesByPV := make(map[string]DataProbe, len(probes))
	for _, probe := range probes {
		probesByPV[targetIdentity(probe.TargetPV)] = probe
	}
	previous := ""
	seenHandles := map[string]bool{}
	for index := range backends {
		backend := &backends[index]
		probe, exists := probesByPV[targetIdentity(backend.DerivedFrom)]
		identity := backend.SourceKind + "\x00" + targetIdentity(backend.DerivedFrom)
		if !exists || previous != "" && identity <= previous || seenHandles[backend.ArtifactHandleSHA256] ||
			backend.TargetPVC == nil || backend.TargetPV == nil || *backend.TargetPVC != *probe.Target || *backend.TargetPV != *probe.TargetPV ||
			backend.SourcePV == nil || backend.SourcePV.Name != probe.SourcePVCVolumeName {
			return errors.New("typed provider backend artifacts must have unique signed sources and handles")
		}
		if err := validateBackend(context, backend); err != nil {
			return err
		}
		previous = identity
		seenHandles[backend.ArtifactHandleSHA256] = true
	}
	return nil
}

func validateBackend(context VolumeRestoreContext, backend *BackendArtifactLineage) error {
	if backend == nil || backend.Status != "deleted-and-absent" || !validRuntimeID(backend.ProviderImplementation) || !validVersion(backend.ProviderVersion) ||
		!validDigest(backend.ArtifactHandleSHA256) || backend.SourceKind != "persistent-volume" || backend.DerivedFrom == nil || backend.DerivedFrom.Resource != "persistentvolumes" ||
		backend.DerivedFrom.Namespace != "" || !containsTarget(context.Cleanup.TargetResources, backend.DerivedFrom) || !containsTarget(context.Cleanup.TargetResources, backend.TargetPVC) ||
		!containsTarget(context.Cleanup.TargetResources, backend.TargetPV) || backend.LineageSHA256 != BackendLineageSHA256(MethodCSIDataMover, backend) ||
		backend.SourcePV == nil || backend.SourcePV.Resource != "persistentvolumes" || backend.SourcePV.Namespace != "" || !containsSource(context.Cleanup.SourceResources, backend.SourcePV) ||
		backend.TargetPV == nil || backend.SourcePV.Name == backend.TargetPV.Name || backend.SourcePV.UIDSHA256 == backend.TargetPV.UIDSHA256 ||
		!validDigest(backend.SourceArtifactHandleSHA256) || backend.SourceArtifactHandleSHA256 == backend.ArtifactHandleSHA256 ||
		backend.PresenceObservation == nil || len(backend.AbsenceObservations) != 2 || backend.SourcePresenceObservation == nil || !validEvidence(backend.EvidenceRef, backend.EvidenceSHA256) ||
		backend.EvidenceSHA256 != BackendEvidenceSHA256(backend) {
		return errors.New("typed provider backend artifact lineage is missing or invalid")
	}
	deletedAt, deletedErr := time.Parse(time.RFC3339Nano, backend.DeletedAt)
	cleanupStarted, _ := time.Parse(time.RFC3339Nano, context.Cleanup.CleanupStartedAt)
	cleanupCompleted, _ := time.Parse(time.RFC3339Nano, context.Cleanup.CleanupCompletedAt)
	validationCompleted, _ := time.Parse(time.RFC3339Nano, context.Cleanup.ValidationCompletedAt)
	verified, _ := time.Parse(time.RFC3339Nano, context.Cleanup.VerifiedAt)
	if deletedErr != nil || deletedAt.Before(cleanupStarted) || deletedAt.After(cleanupCompleted) {
		return errors.New("typed provider backend deletion timeline is invalid")
	}
	query := ProviderAbsenceQuerySHA256(backend)
	presence := backend.PresenceObservation
	presenceAt, presenceErr := time.Parse(time.RFC3339Nano, presence.ObservedAt)
	if presenceErr != nil || !validProviderObservation(backend.ArtifactHandleSHA256, presence, query, "present") || presenceAt.Before(validationCompleted) || presenceAt.After(cleanupStarted) {
		return errors.New("typed provider backend presence observation is invalid")
	}
	seenRequests := map[string]bool{presence.RequestSHA256: true}
	previous := deletedAt
	previousHash := ""
	for index, observation := range backend.AbsenceObservations {
		observedAt, err := time.Parse(time.RFC3339Nano, observation.ObservedAt)
		if err != nil || !validProviderObservation(backend.ArtifactHandleSHA256, &observation, query, "absent") ||
			observation.AdapterExecutableSHA256 != presence.AdapterExecutableSHA256 || observation.ObservationSHA256 == previousHash ||
			seenRequests[observation.RequestSHA256] ||
			!observedAt.After(previous) || observedAt.After(verified) || observedAt.Before(cleanupCompleted) ||
			index > 0 && observedAt.Sub(previous) < providerAbsenceMinimumInterval {
			return errors.New("typed provider backend absence observations are invalid or unordered")
		}
		previous = observedAt
		previousHash = observation.ObservationSHA256
		seenRequests[observation.RequestSHA256] = true
	}
	sourcePresence := backend.SourcePresenceObservation
	sourcePresenceAt, sourcePresenceErr := time.Parse(time.RFC3339Nano, sourcePresence.ObservedAt)
	sourceQuery := ProviderSourceContinuityQuerySHA256(backend)
	if sourcePresenceErr != nil || !validProviderObservation(backend.SourceArtifactHandleSHA256, sourcePresence, sourceQuery, "present") ||
		sourcePresence.AdapterExecutableSHA256 != presence.AdapterExecutableSHA256 || !sourcePresenceAt.After(previous) ||
		sourcePresenceAt.Before(cleanupCompleted) || sourcePresenceAt.After(verified) || seenRequests[sourcePresence.RequestSHA256] {
		return errors.New("typed provider source continuity observation is invalid")
	}
	return nil
}

func validProviderObservation(expectedHandleSHA256 string, observation *ProviderObservation, query, status string) bool {
	return observation != nil && observation.Status == status && observation.ArtifactHandleSHA256 == expectedHandleSHA256 &&
		validDigest(observation.RequestSHA256) && validDigest(observation.AdapterExecutableSHA256) && observation.QuerySHA256 == query &&
		observation.ObservationSHA256 == ProviderObservationSHA256(query, observation.RequestSHA256, observation.AdapterExecutableSHA256, status, observation.ObservedAt) &&
		canonicalTime(observation.ObservedAt) && validEvidence(observation.EvidenceRef, observation.EvidenceSHA256)
}

func validateDataUploadBindings(receipt *VolumeReceipt) error {
	upload := &receipt.DataUpload
	result := &receipt.DataUploadResult
	lineage := &receipt.Lineage
	if upload.GVR != DataUploadGVR || upload.SourcePVCGVR != CoreV1PVCGVR || upload.SourcePVC == nil || !containsSource(receipt.Context.Cleanup.SourceResources, upload.SourcePVC) ||
		upload.Namespace != receipt.Context.VeleroNamespace || !validName(upload.Name) || !validDigest(upload.UIDSHA256) || !validDigest(upload.ResourceVersionSHA256) || upload.OwnerBackupUIDSHA256 != receipt.Context.BackupUIDSHA256 ||
		upload.BackupUIDLabelSHA256 != receipt.Context.BackupUIDSHA256 || upload.BackupNameLabel != validLabelValue(receipt.Context.BackupID) ||
		upload.SourcePVCUIDLabelSHA256 != upload.SourcePVC.UIDSHA256 || upload.SnapshotType != "CSI" || upload.BackupStorageLocation != receipt.Context.BackupStorageLocation ||
		!builtInDataMover(upload.DataMover) || upload.Phase != "Completed" || upload.Message != "" || upload.NodeOS != "linux" || upload.BytesDone <= 0 || upload.BytesDone != upload.TotalBytes ||
		!validDigest(upload.VolumeSnapshotSHA256) || !validDigest(upload.StorageClassSHA256) || upload.SnapshotClassSHA256 != "" && !validDigest(upload.SnapshotClassSHA256) ||
		!validRuntimeID(upload.Driver) || !validDigest(upload.SnapshotIDSHA256) || !validDigest(upload.OperationIDSHA256) || !validDigest(upload.ArchivedObjectSHA256) ||
		upload.DataMoverConfigSHA256 != receipt.Context.BackupUploaderConfigSHA256 || upload.OperationTimeout != receipt.Context.CSISnapshotTimeout ||
		upload.DataMoverResultSHA256 != "" && !validDigest(upload.DataMoverResultSHA256) ||
		!validEvidence(upload.EvidenceRef, upload.EvidenceSHA256) || upload.EvidenceSHA256 != DataUploadEvidenceSHA256(upload) || lineage.ValidatedBytes != upload.TotalBytes {
		return errors.New("Velero DataUpload proof is invalid")
	}
	uploadStarted, uploadStartErr := time.Parse(time.RFC3339Nano, upload.StartedAt)
	uploadCompleted, uploadCompleteErr := time.Parse(time.RFC3339Nano, upload.CompletedAt)
	backupCompleted, _ := time.Parse(time.RFC3339Nano, receipt.Context.BackupCompletedAt)
	retainedAt, retainedErr := time.Parse(time.RFC3339Nano, upload.RetainedAfterRestoreCleanupAt)
	verifiedAt, _ := time.Parse(time.RFC3339Nano, receipt.Context.Cleanup.VerifiedAt)
	operationTimeout, timeoutErr := time.ParseDuration(upload.OperationTimeout)
	if uploadStartErr != nil || uploadCompleteErr != nil || retainedErr != nil || timeoutErr != nil || operationTimeout <= 0 ||
		!uploadStarted.Before(uploadCompleted) || uploadCompleted.After(backupCompleted) || retainedAt.Before(verifiedAt) {
		return errors.New("Velero DataUpload proof timeline is invalid")
	}
	if result.Status != "generated-consumed-velero-cleaned" || result.GVR != CoreV1CMGVR || result.Object == nil || result.Object.Namespace != receipt.Context.VeleroNamespace || !containsTarget(receipt.Context.Cleanup.TargetResources, result.Object) ||
		len(receipt.Context.Cleanup.VeleroAutoCleanedResources) != 1 || receipt.Context.Cleanup.VeleroAutoCleanedResources[0] != *result.Object ||
		result.DataUploadUIDSHA256 != upload.UIDSHA256 || result.DataUploadName != upload.Name || result.ArchivedDataUploadSHA256 != upload.ArchivedObjectSHA256 ||
		result.RestoreUIDSHA256 != receipt.Context.RestoreUIDSHA256 || result.RestoreUIDLabelSHA256 != receipt.Context.RestoreUIDSHA256 ||
		result.RestoreUIDDataKeySHA256 != receipt.Context.RestoreUIDSHA256 || result.PVCNamespaceNameLabel != validLabelValue(upload.SourcePVC.Namespace+"."+upload.SourcePVC.Name) ||
		result.ResourceUsage != "DataUpload" || result.SourcePVC == nil || *result.SourcePVC != *upload.SourcePVC || result.Object.Namespace != upload.Namespace ||
		!strings.HasPrefix(result.Object.Name, upload.Name+"-") ||
		result.BackupStorageLocation != upload.BackupStorageLocation || result.DataMover != upload.DataMover || result.SnapshotIDSHA256 != upload.SnapshotIDSHA256 ||
		result.SourceNamespace != upload.SourcePVC.Namespace || result.SnapshotSize != upload.TotalBytes || result.NodeOS != upload.NodeOS ||
		result.DataMoverResultSHA256 != upload.DataMoverResultSHA256 || !validDigest(result.ResultPayloadSHA256) || !validEvidence(result.EvidenceRef, result.EvidenceSHA256) ||
		result.EvidenceSHA256 != DataUploadResultEvidenceSHA256(result) {
		return errors.New("Velero DataUploadResult proof is invalid")
	}
	// ObservedAt is an API-server creationTimestamp, Restore status is written
	// by the Velero controller, and VeleroAutoDeletedAt is stamped by the local
	// collector after exact absence. Their cross-clock order is not evidence;
	// preserve canonical forms and only keep the local cleanup boundary.
	resultAutoDeleted, autoDeletedErr := time.Parse(time.RFC3339Nano, result.VeleroAutoDeletedAt)
	validationCompleted, _ := time.Parse(time.RFC3339Nano, receipt.Context.Cleanup.ValidationCompletedAt)
	if autoDeletedErr != nil || !canonicalTime(result.ObservedAt) || !canonicalTime(result.VeleroAutoDeletedAt) ||
		resultAutoDeleted.After(validationCompleted) {
		return errors.New("Velero DataUploadResult observation and auto-deletion timeline is invalid")
	}
	if len(lineage.Helpers) != 1 || lineage.Helpers[0].DataDownload == nil {
		return errors.New("Velero DataUploadResult is not linked to one DataDownload")
	}
	data := lineage.Helpers[0].DataDownload
	if data.DataUploadUIDSHA256 != upload.UIDSHA256 || data.ArchivedDataUploadSHA256 != upload.ArchivedObjectSHA256 ||
		data.DataUploadResultPayloadSHA256 != result.ResultPayloadSHA256 || *data.DataUploadResultObject != *result.Object ||
		data.SnapshotIDSHA256 != upload.SnapshotIDSHA256 || data.SnapshotSize != upload.TotalBytes || data.BackupStorageLocation != upload.BackupStorageLocation {
		return errors.New("DataDownload does not match its exact archived DataUploadResult")
	}
	return nil
}

func sourceInventory(resources []SourceResource, kind string) map[string]SourceResource {
	result := map[string]SourceResource{}
	for index := range resources {
		resource := resources[index]
		if resource.Resource == kind {
			result[objectIdentity(resource.Resource, resource.Namespace, resource.Name)] = resource
		}
	}
	return result
}

func targetInventory(resources []TargetResource, kind string) map[string]TargetResource {
	result := map[string]TargetResource{}
	for index := range resources {
		resource := resources[index]
		if resource.Resource == kind {
			result[objectIdentity(resource.Resource, resource.Namespace, resource.Name)] = resource
		}
	}
	return result
}

func containsSource(resources []SourceResource, candidate *SourceResource) bool {
	if candidate == nil {
		return false
	}
	for index := range resources {
		if resources[index] == *candidate {
			return true
		}
	}
	return false
}

func containsTarget(resources []TargetResource, candidate *TargetResource) bool {
	if candidate == nil {
		return false
	}
	for index := range resources {
		if resources[index] == *candidate {
			return true
		}
	}
	return false
}

func validDigest(value string) bool    { return digestPattern.MatchString(value) }
func validName(value string) bool      { return len(value) <= 253 && namePattern.MatchString(value) }
func validRuntimeID(value string) bool { return idPattern.MatchString(value) }
func validVersion(value string) bool {
	return strings.HasPrefix(value, "v") && len(value) > 1 && validRuntimeID(value)
}
func validEvidence(ref, hash string) bool { return validRuntimeID(ref) && validDigest(hash) }
func canonicalTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.UTC().Format(time.RFC3339Nano) == value
}
func builtInDataMover(value string) bool { return value == "" || value == "velero" }

func validLabelValue(value string) string {
	if len(value) <= 63 {
		return value
	}
	digest := sha256.Sum256([]byte(value))
	return value[:57] + hex.EncodeToString(digest[:])[:6]
}

// SortReceiptCanonical orders all set-like receipt members before hashing.
func SortReceiptCanonical(receipt *VolumeReceipt) {
	if receipt == nil {
		return
	}
	sort.Slice(receipt.Context.Cleanup.SourceResources, func(left, right int) bool {
		return objectIdentity(receipt.Context.Cleanup.SourceResources[left].Resource, receipt.Context.Cleanup.SourceResources[left].Namespace, receipt.Context.Cleanup.SourceResources[left].Name) <
			objectIdentity(receipt.Context.Cleanup.SourceResources[right].Resource, receipt.Context.Cleanup.SourceResources[right].Namespace, receipt.Context.Cleanup.SourceResources[right].Name)
	})
	sort.Slice(receipt.Context.Cleanup.TargetResources, func(left, right int) bool {
		return objectIdentity(receipt.Context.Cleanup.TargetResources[left].Resource, receipt.Context.Cleanup.TargetResources[left].Namespace, receipt.Context.Cleanup.TargetResources[left].Name) <
			objectIdentity(receipt.Context.Cleanup.TargetResources[right].Resource, receipt.Context.Cleanup.TargetResources[right].Namespace, receipt.Context.Cleanup.TargetResources[right].Name)
	})
	sort.Slice(receipt.Lineage.Probes, func(left, right int) bool {
		return sourceIdentity(receipt.Lineage.Probes[left].Source) < sourceIdentity(receipt.Lineage.Probes[right].Source)
	})
	sort.Slice(receipt.Lineage.Helpers, func(left, right int) bool {
		return targetIdentity(receipt.Lineage.Helpers[left].Object) < targetIdentity(receipt.Lineage.Helpers[right].Object)
	})
	sort.Slice(receipt.Lineage.BackendArtifacts, func(left, right int) bool {
		return receipt.Lineage.BackendArtifacts[left].SourceKind+"\x00"+targetIdentity(receipt.Lineage.BackendArtifacts[left].DerivedFrom) <
			receipt.Lineage.BackendArtifacts[right].SourceKind+"\x00"+targetIdentity(receipt.Lineage.BackendArtifacts[right].DerivedFrom)
	})
}
