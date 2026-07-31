// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package velero118

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
)

// ObserveDataUploadResult establishes a gap-free LIST+WATCH before a Restore
// exists and returns the one exact DataUploadResult ADDED event. Velero deletes
// these ConfigMaps before publishing terminal Restore status, so polling or
// post-restore discovery cannot prove this lineage.
func ObserveDataUploadResult(
	ctx context.Context,
	reader KubernetesWatchReader,
	readyBarrier DataUploadResultObservationReadyBarrier,
	request DataUploadResultObservationRequest,
	timeout time.Duration,
	poll time.Duration,
	clock Clock,
) (DataUploadResultObservation, error) {
	if err := validateDataUploadResultObservationRequest(request); err != nil {
		return DataUploadResultObservation{}, err
	}
	if reader == nil || readyBarrier == nil || timeout <= 0 || poll <= 0 || poll > timeout {
		return DataUploadResultObservation{}, errors.New("DataUploadResult observer dependency or timing is invalid")
	}
	if clock == nil {
		clock = SystemClock()
	}
	reader = withWatchReadRetries(reader, clock)
	observationContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ctx = observationContext
	if _, err := reader.Get(ctx, restoreproof.VeleroV1RestoreGVR, request.VeleroNamespace, request.RestoreName); !errors.Is(err, ErrNotFound) {
		return DataUploadResultObservation{}, errors.New("Velero Restore must be absent before DataUploadResult watch")
	}
	restoreAbsent, err := reader.ConfirmAbsent(ctx, restoreproof.VeleroV1RestoreGVR, request.VeleroNamespace, request.RestoreName)
	if err != nil || !restoreAbsent {
		return DataUploadResultObservation{}, errors.New("Velero Restore pre-watch absence was not confirmed")
	}
	selector := strings.Join([]string{
		"velero.io/pvc-namespace-name=" + veleroValidLabelName(request.SourceNamespace+"."+request.SourcePVC),
		"velero.io/resource-usage=DataUpload",
	}, ",")
	initialPayload, err := reader.ListPage(ctx, restoreproof.CoreV1CMGVR, request.VeleroNamespace, selector, "", 100)
	if err != nil {
		return DataUploadResultObservation{}, errors.New("establish initial DataUploadResult list")
	}
	initialPage, err := DecodeListPage(initialPayload, "v1", "ConfigMapList")
	if err != nil || initialPage.ResourceVersion == "" || initialPage.Continue != "" || len(initialPage.Items) != 0 {
		return DataUploadResultObservation{}, errors.New("initial DataUploadResult list is not an exact empty fence")
	}
	watchStartedAt := canonicalTimestamp(clock.Now())
	requestSHA256 := requestJSONSHA256(request)
	ready := DataUploadResultObservationReady{
		SchemaVersion: DataUploadResultObservationReadySchemaVersion,
		Status:        DataUploadResultObservationReadyStatus, WatchStartedAt: watchStartedAt, RequestSHA256: requestSHA256,
	}
	if err := readyBarrier.ReadyForRestore(ctx, ready); err != nil {
		return DataUploadResultObservation{}, errors.New("publish DataUploadResult watch readiness")
	}

	deadline := clock.Now().Add(timeout)
	resourceVersion := initialPage.ResourceVersion
	restoreUID := ""
	for clock.Now().Before(deadline) {
		events, nextResourceVersion, watchErr := reader.WatchPage(ctx, restoreproof.CoreV1CMGVR, request.VeleroNamespace, selector, resourceVersion, 5)
		if watchErr != nil {
			return DataUploadResultObservation{}, errors.New("watch exact Velero DataUploadResult collection")
		}
		if nextResourceVersion == "" {
			return DataUploadResultObservation{}, errors.New("DataUploadResult watch lost its resourceVersion")
		}
		resourceVersion = nextResourceVersion
		var captured []byte
		capturedName := ""
		capturedUID := ""
		for _, event := range events {
			metadata, decodeErr := decodeWatchedConfigMapMetadata(event.Object)
			if decodeErr != nil || metadata.Namespace != request.VeleroNamespace {
				return DataUploadResultObservation{}, errors.New("decode watched Velero ConfigMap")
			}
			if metadata.Labels["velero.io/pvc-namespace-name"] != veleroValidLabelName(request.SourceNamespace+"."+request.SourcePVC) ||
				metadata.Labels["velero.io/resource-usage"] != "DataUpload" {
				return DataUploadResultObservation{}, errors.New("DataUploadResult watch selector contract was violated")
			}
			if !strings.HasPrefix(metadata.Name, request.DataUploadName+"-") {
				return DataUploadResultObservation{}, errors.New("DataUploadResult watch observed a gap, replacement, or ambiguity")
			}
			switch event.Type {
			case "ADDED":
				if captured != nil || metadata.DeletionTimestamp != nil {
					return DataUploadResultObservation{}, errors.New("DataUploadResult watch observed a gap, replacement, or ambiguity")
				}
				captured = append([]byte(nil), event.Object...)
				capturedName = metadata.Name
				capturedUID = metadata.UID
			case "MODIFIED", "DELETED":
				if captured == nil || metadata.Name != capturedName || metadata.UID != capturedUID {
					return DataUploadResultObservation{}, errors.New("DataUploadResult watch observed a gap, replacement, or ambiguity")
				}
			default:
				return DataUploadResultObservation{}, errors.New("DataUploadResult watch event type is invalid")
			}
		}
		if captured != nil {
			restorePayload, readErr := reader.Get(ctx, restoreproof.VeleroV1RestoreGVR, request.VeleroNamespace, request.RestoreName)
			if readErr != nil {
				return DataUploadResultObservation{}, errors.New("read Restore bound to DataUploadResult event")
			}
			restoreObject, decodeErr := DecodeRestore(restorePayload)
			configMap, configMapErr := DecodeConfigMap(captured)
			if decodeErr != nil || configMapErr != nil || restoreObject.Identity.Metadata.Name != request.RestoreName || restoreObject.Identity.Metadata.Namespace != request.VeleroNamespace ||
				restoreObject.Identity.Metadata.DeletionTimestamp != nil || restoreUID != "" && restoreUID != restoreObject.Identity.Metadata.UID ||
				configMap.Identity.Metadata.Labels["velero.io/restore-uid"] != veleroValidLabelName(restoreObject.Identity.Metadata.UID) || len(configMap.Data) != 1 {
				return DataUploadResultObservation{}, errors.New("DataUploadResult event is not bound to the exact Restore")
			}
			restoreUID = restoreObject.Identity.Metadata.UID
			payload, exists := configMap.Data[restoreUID]
			result, resultErr := DecodeDataUploadResult([]byte(payload))
			if !exists || resultErr != nil || result.SourceNamespace != request.SourceNamespace || !canonicalTime(configMap.Identity.Metadata.CreationTimestamp) {
				return DataUploadResultObservation{}, errors.New("DataUploadResult event payload or creation time is invalid")
			}
			if !canonicalTime(restoreObject.Identity.Metadata.CreationTimestamp) || !canonicalTime(restoreObject.Status.StartTimestamp) {
				return DataUploadResultObservation{}, errors.New("Restore creation or start time is unavailable for DataUploadResult watch binding")
			}
			// API-server and Velero-controller timestamps come from clocks that
			// need not agree with this observer. The exact empty LIST fence,
			// readiness barrier, gap-free watch, and Restore UID binding are the
			// causal proof that this object belongs to the subsequently created
			// Restore; the remote timestamps remain canonical identity evidence.
			observation := DataUploadResultObservation{
				SchemaVersion:  DataUploadResultObservationSchemaVersion,
				WatchStartedAt: watchStartedAt,
				ObservedAt:     configMap.Identity.Metadata.CreationTimestamp,
				CapturedAt:     canonicalTimestamp(clock.Now()),
				RequestSHA256:  requestSHA256,
				EventType:      "ADDED",
				Object:         append(json.RawMessage(nil), captured...),
				ObjectSHA256:   canonicalJSONSHA256(captured),
				EvidenceRef:    request.EvidencePrefix + "/velero-data-upload-result-observation",
			}
			observation.EvidenceSHA256 = dataUploadResultObservationEvidenceSHA256(observation)
			if err := validateDataUploadResultObservation(observation); err != nil {
				return DataUploadResultObservation{}, err
			}
			return observation, nil
		}

		restorePayload, restoreErr := reader.Get(ctx, restoreproof.VeleroV1RestoreGVR, request.VeleroNamespace, request.RestoreName)
		if restoreErr == nil {
			restoreObject, decodeErr := DecodeRestore(restorePayload)
			if decodeErr != nil || restoreObject.Identity.Metadata.DeletionTimestamp != nil || restoreUID != "" && restoreUID != restoreObject.Identity.Metadata.UID {
				return DataUploadResultObservation{}, errors.New("observed Velero Restore was replaced")
			}
			restoreUID = restoreObject.Identity.Metadata.UID
			if terminalRestorePhase(restoreObject.Status.Phase) {
				return DataUploadResultObservation{}, errors.New("Velero Restore completed before DataUploadResult ADDED event")
			}
		} else if !errors.Is(restoreErr, ErrNotFound) {
			return DataUploadResultObservation{}, errors.New("read watched Velero Restore")
		}
		if err := clock.Wait(ctx, poll); err != nil {
			return DataUploadResultObservation{}, errors.New("wait between DataUploadResult watch pages")
		}
	}
	return DataUploadResultObservation{}, errors.New("Velero DataUploadResult watch timed out")
}

func decodeWatchedConfigMapMetadata(payload []byte) (Metadata, error) {
	var envelope objectEnvelope
	if err := strictjson.Decode(payload, &envelope); err != nil || envelope.APIVersion != "v1" || envelope.Kind != "ConfigMap" ||
		envelope.Metadata.Name == "" || envelope.Metadata.Namespace == "" || envelope.Metadata.UID == "" || envelope.Metadata.ResourceVersion == "" {
		return Metadata{}, errors.New("watched ConfigMap metadata is invalid")
	}
	return envelope.Metadata, nil
}

func validateDataUploadResultObservationRequest(request DataUploadResultObservationRequest) error {
	if request.SchemaVersion != DataUploadResultObservationRequestSchemaVersion || !safeName(request.VeleroNamespace) || !safeName(request.RestoreName) ||
		!safeName(request.SourceNamespace) || !safeName(request.SourcePVC) || !safeName(request.DataUploadName) || !safeEvidencePrefix(request.EvidencePrefix) {
		return errors.New("DataUploadResult observation request is invalid")
	}
	return nil
}

func validateDataUploadResultObservation(observation DataUploadResultObservation) error {
	if observation.SchemaVersion != DataUploadResultObservationSchemaVersion || !canonicalTime(observation.WatchStartedAt) || !canonicalTime(observation.ObservedAt) || !canonicalTime(observation.CapturedAt) ||
		!validSHA256(observation.RequestSHA256) || observation.EventType != "ADDED" || len(observation.Object) == 0 ||
		!validSHA256(observation.ObjectSHA256) || observation.ObjectSHA256 != canonicalJSONSHA256(observation.Object) ||
		!validRuntimeID(observation.EvidenceRef) || !validSHA256(observation.EvidenceSHA256) ||
		observation.EvidenceSHA256 != dataUploadResultObservationEvidenceSHA256(observation) {
		return errors.New("DataUploadResult observation is invalid")
	}
	// These are the only two timestamps emitted by this observer's clock.
	// Do not order either one against API-server creationTimestamp values.
	watchStartedAt, _ := time.Parse(time.RFC3339Nano, observation.WatchStartedAt)
	capturedAt, _ := time.Parse(time.RFC3339Nano, observation.CapturedAt)
	if capturedAt.Before(watchStartedAt) {
		return errors.New("DataUploadResult observation timeline is invalid")
	}
	return nil
}

func dataUploadResultObservationEvidenceSHA256(observation DataUploadResultObservation) string {
	observation.EvidenceSHA256 = ""
	payload, err := json.Marshal(observation)
	if err != nil {
		return ""
	}
	return restoreproof.SHA256(string(payload))
}

func terminalRestorePhase(phase string) bool {
	switch phase {
	case "Completed", "PartiallyFailed", "Failed", "FailedValidation":
		return true
	default:
		return false
	}
}
