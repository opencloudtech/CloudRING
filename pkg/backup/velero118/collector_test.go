// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package velero118

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
)

func TestBuildSourceBaselineRejectsNilReader(t *testing.T) {
	t.Parallel()
	request := BaselineRequest{
		SchemaVersion: BaselineRequestSchemaVersion, SourceNamespace: "source", SourcePVC: "volume", EvidencePrefix: "runtime/task22a",
	}
	if _, err := BuildSourceBaseline(t.Context(), nil, request, nil); err == nil {
		t.Fatal("nil Kubernetes reader unexpectedly passed")
	}
}

func TestEvidencePrefixGeneratedReferenceBoundary(t *testing.T) {
	t.Parallel()
	request := validCollectionRequest()
	request.EvidencePrefix = strings.Repeat("a", 229)
	if err := validateRequest(request); err != nil {
		t.Fatalf("229-byte evidence prefix rejected: %v", err)
	}
	request.EvidencePrefix += "a"
	if err := validateRequest(request); err == nil {
		t.Fatal("230-byte evidence prefix unexpectedly passed")
	}
	baselineRequest := baselineRequestFromCollection(validCollectionRequest())
	baselineRequest.EvidencePrefix = strings.Repeat("a", 229)
	if err := validateBaselineRequest(baselineRequest); err != nil {
		t.Fatalf("229-byte baseline evidence prefix rejected: %v", err)
	}
	baselineRequest.EvidencePrefix += "a"
	if err := validateBaselineRequest(baselineRequest); err == nil {
		t.Fatal("230-byte baseline evidence prefix unexpectedly passed")
	}
}

func TestCollectCSIDataMoverVolumeLineageEndToEnd(t *testing.T) {
	t.Parallel()
	reader, archive := validRuntimeFixture(t)
	clock := &fakeClock{now: mustTime(t, "2026-07-14T12:00:00Z")}
	request := validCollectionRequest()
	baseline, err := BuildSourceBaseline(t.Context(), reader, baselineRequestFromCollection(request), clock)
	if err != nil {
		t.Fatalf("BuildSourceBaseline() error = %v", err)
	}
	clock.now = mustTime(t, "2026-07-14T12:02:03Z")
	clock.onFirstWait = func() { reader.deleted = true }
	probe := fakeProbeObserver{observation: ProbeObservation{
		SchemaVersion: AdapterResponseSchemaVersion, Implementation: "cloudring-volume-probe", Version: "v1",
		HashAlgorithm: "sha256", SourceSHA256: digest("tenant-data"), TargetSHA256: digest("tenant-data"), ValidatedBytes: 4096,
		StartedAt: "2026-07-14T12:02:01Z", CompletedAt: "2026-07-14T12:02:02Z", EvidenceRef: "runtime/task22a/data-probe", EvidenceSHA256: digest("probe-evidence"),
	}}
	provider := &fakeBackendObserver{clock: clock}
	readsAtBarrier := 0
	barrier := &fakePostCleanupBarrier{fakeCleanupBarrier: fakeCleanupBarrier{onReady: func(notice CleanupReady) error {
		if provider.calls != 1 || notice.SchemaVersion != CleanupReadySchemaVersion || notice.Status != CleanupReadyStatus {
			return errors.New("cleanup barrier was published out of order")
		}
		readsAtBarrier = reader.getCalls
		return nil
	}}}
	receipt, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, probe, provider, barrier, request, baseline, archive, clock)
	if err != nil {
		t.Fatalf("CollectCSIDataMoverVolumeLineage() error = %v", err)
	}
	if err := restoreproof.ValidateCSIDataMoverVolumeReceipt(&receipt); err != nil {
		t.Fatalf("ValidateCSIDataMoverVolumeReceipt() error = %v", err)
	}
	assertReceiptMatchesSchema(t, receipt)
	if provider.calls != 4 {
		t.Fatalf("provider calls = %d, want 4", provider.calls)
	}
	if barrier.calls != 1 || barrier.postCleanupCalls != 1 || readsAtBarrier == 0 || reader.getCalls <= readsAtBarrier {
		t.Fatalf("cleanup barrier ordering: calls=%d postCleanupCalls=%d readsAtBarrier=%d finalReads=%d", barrier.calls, barrier.postCleanupCalls, readsAtBarrier, reader.getCalls)
	}
	if len(receipt.Lineage.BackendArtifacts) != 1 || len(receipt.Lineage.BackendArtifacts[0].AbsenceObservations) != 2 {
		t.Fatalf("provider absence proof = %#v", receipt.Lineage.BackendArtifacts)
	}
	firstAbsenceAt, err := time.Parse(time.RFC3339Nano, receipt.Lineage.BackendArtifacts[0].AbsenceObservations[0].ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	secondAbsenceAt, err := time.Parse(time.RFC3339Nano, receipt.Lineage.BackendArtifacts[0].AbsenceObservations[1].ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	if separation := secondAbsenceAt.Sub(firstAbsenceAt); separation < providerAbsenceMinimumInterval+providerAbsenceClockSkewMargin {
		t.Fatalf("provider absence proof has no wall-clock skew margin: %s", separation)
	}
	if receipt.DataUpload.ArchivedObjectSHA256 == "" || receipt.Lineage.Helpers[0].DataDownload.DataUploadResultPayloadSHA256 == "" {
		t.Fatal("archive/result cross-binding is absent")
	}
	tampered := cloneReceipt(t, receipt)
	tampered.Lineage.Helpers[0].DataDownload.SnapshotIDSHA256 = digest("other-snapshot")
	tampered.ReceiptSHA256 = restoreproof.ReceiptSHA256(tampered)
	if err := restoreproof.ValidateCSIDataMoverVolumeReceipt(&tampered); err == nil {
		t.Fatal("tampered receipt unexpectedly validated")
	}

	namespaceTampered := cloneReceipt(t, receipt)
	namespaceTampered.Context.VeleroNamespace = "other"
	namespaceTampered.ReceiptSHA256 = restoreproof.ReceiptSHA256(namespaceTampered)
	if err := restoreproof.ValidateCSIDataMoverVolumeReceipt(&namespaceTampered); err == nil {
		t.Fatal("cross-namespace receipt unexpectedly validated")
	}

	sourceBindingTampered := cloneReceipt(t, receipt)
	sourceBindingTampered.Lineage.Probes[0].SourcePVCVolumeName = "unrelated-pv"
	refreshLineageDigests(&sourceBindingTampered.Lineage)
	sourceBindingTampered.ReceiptSHA256 = restoreproof.ReceiptSHA256(sourceBindingTampered)
	if err := restoreproof.ValidateCSIDataMoverVolumeReceipt(&sourceBindingTampered); err == nil {
		t.Fatal("unrelated source PV binding unexpectedly validated")
	}

	samePVTampered := cloneReceipt(t, receipt)
	sameBackend := &samePVTampered.Lineage.BackendArtifacts[0]
	sameTargetPV := *sameBackend.TargetPV
	sameSourcePV := restoreproof.SourceResource{
		Resource: "persistentvolumes", Namespace: "", Name: sameTargetPV.Name, UIDSHA256: sameTargetPV.UIDSHA256,
		ResourceVersionBeforeSHA256: sameTargetPV.ResourceVersionSHA256, ResourceVersionAfterSHA256: sameTargetPV.ResourceVersionSHA256,
		StateBeforeSHA256: sameTargetPV.ValidatedStateSHA256, StateAfterSHA256: sameTargetPV.ValidatedStateSHA256,
	}
	for index := range samePVTampered.Context.Cleanup.SourceResources {
		if samePVTampered.Context.Cleanup.SourceResources[index].Resource == "persistentvolumes" {
			samePVTampered.Context.Cleanup.SourceResources[index] = sameSourcePV
		}
	}
	sameBackend.SourcePV = &sameSourcePV
	samePVTampered.Lineage.Probes[0].SourcePVCVolumeName = sameTargetPV.Name
	sameBackend.LineageSHA256 = restoreproof.BackendLineageSHA256(restoreproof.MethodCSIDataMover, sameBackend)
	refreshLineageDigests(&samePVTampered.Lineage)
	samePVTampered.ReceiptSHA256 = restoreproof.ReceiptSHA256(samePVTampered)
	if err := restoreproof.ValidateCSIDataMoverVolumeReceipt(&samePVTampered); err == nil {
		t.Fatal("same source and target PV unexpectedly validated")
	}

	replayedRequest := cloneReceipt(t, receipt)
	backendProof := &replayedRequest.Lineage.BackendArtifacts[0]
	backendProof.SourcePresenceObservation.RequestSHA256 = backendProof.PresenceObservation.RequestSHA256
	backendProof.SourcePresenceObservation.ObservationSHA256 = restoreproof.ProviderObservationSHA256(
		backendProof.SourcePresenceObservation.QuerySHA256,
		backendProof.SourcePresenceObservation.RequestSHA256,
		backendProof.SourcePresenceObservation.AdapterExecutableSHA256,
		backendProof.SourcePresenceObservation.Status,
		backendProof.SourcePresenceObservation.ObservedAt,
	)
	backendProof.EvidenceSHA256 = restoreproof.BackendEvidenceSHA256(backendProof)
	replayedRequest.ReceiptSHA256 = restoreproof.ReceiptSHA256(replayedRequest)
	if err := restoreproof.ValidateCSIDataMoverVolumeReceipt(&replayedRequest); err == nil {
		t.Fatal("replayed provider request digest unexpectedly validated")
	}

	reordered := cloneReceipt(t, receipt)
	reordered.Context.Cleanup.SourceResources[0], reordered.Context.Cleanup.SourceResources[1] = reordered.Context.Cleanup.SourceResources[1], reordered.Context.Cleanup.SourceResources[0]
	reordered.ReceiptSHA256 = restoreproof.ReceiptSHA256(reordered)
	if err := restoreproof.ValidateCSIDataMoverVolumeReceipt(&reordered); err == nil {
		t.Fatal("non-canonical source inventory order unexpectedly validated")
	}

	lineageEvidenceTampered := cloneReceipt(t, receipt)
	lineageEvidenceTampered.Lineage.EvidenceSHA256 = digest("unbound-lineage-evidence")
	lineageEvidenceTampered.ReceiptSHA256 = restoreproof.ReceiptSHA256(lineageEvidenceTampered)
	if err := restoreproof.ValidateCSIDataMoverVolumeReceipt(&lineageEvidenceTampered); err == nil {
		t.Fatal("unbound lineage evidence digest unexpectedly validated")
	}
}

func cloneReceipt(t *testing.T, receipt restoreproof.VolumeReceipt) restoreproof.VolumeReceipt {
	t.Helper()
	payload := mustJSON(t, receipt)
	var clone restoreproof.VolumeReceipt
	if err := json.Unmarshal(payload, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func refreshLineageDigests(lineage *restoreproof.DataLineage) {
	lineage.ProbeSetSHA256 = restoreproof.ProbeSetSHA256(lineage.Probes)
	lineage.AggregateDataSHA256 = restoreproof.AggregateDataSHA256(lineage.Probes)
	lineage.ProviderAbsenceSetSHA256 = restoreproof.ProviderAbsenceSetSHA256(lineage.BackendArtifacts)
	lineage.EvidenceSHA256 = restoreproof.DataLineageEvidenceSHA256(lineage)
}

func assertReceiptMatchesSchema(t *testing.T, receipt restoreproof.VolumeReceipt) {
	t.Helper()
	schema, err := jsonschema.NewCompiler().Compile("../../../contracts/backup-proof/restore-proof.schema.json")
	if err != nil {
		t.Fatalf("compile restore-proof schema: %v", err)
	}
	payload := mustJSON(t, receipt)
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("decode generated receipt for schema validation: %v", err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("generated receipt does not match restore-proof schema: %v", err)
	}
}

func TestCollectorFailsClosedOnSourceMutationReplacementAndProviderPresence(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*fakeReader, *fakeBackendObserver)
	}{
		{name: "source mutation", mutate: func(reader *fakeReader, _ *fakeBackendObserver) {
			reader.mutateSourceOnCleanup = true
		}},
		{name: "target replacement", mutate: func(reader *fakeReader, _ *fakeBackendObserver) {
			reader.replaceTargetOnCleanup = true
		}},
		{name: "provider remains present", mutate: func(_ *fakeReader, provider *fakeBackendObserver) {
			provider.remainPresent = true
		}},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			reader, archive := validRuntimeFixture(t)
			clock := &fakeClock{now: mustTime(t, "2026-07-14T12:00:00Z")}
			request := validCollectionRequest()
			baseline, err := BuildSourceBaseline(t.Context(), reader, baselineRequestFromCollection(request), clock)
			if err != nil {
				t.Fatal(err)
			}
			clock.now = mustTime(t, "2026-07-14T12:02:03Z")
			clock.onFirstWait = func() { reader.deleted = true }
			provider := &fakeBackendObserver{clock: clock}
			test.mutate(reader, provider)
			probe := fakeProbeObserver{observation: validProbeObservationFixture()}
			if _, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, probe, provider, &fakeCleanupBarrier{}, request, baseline, archive, clock); err == nil {
				t.Fatal("invalid live state unexpectedly produced a receipt")
			}
		})
	}
}

func TestCleanupBarrierRejectsSharedSourceAndTargetBackend(t *testing.T) {
	t.Parallel()
	reader, archive, request, baseline, clock := preparedCollectionFixture(t)
	key := readerKey(restoreproof.CoreV1PVGVR, "", "source-pv")
	reader.objects[key] = bytes.Replace(reader.objects[key], []byte("source-provider-volume-handle"), []byte("provider-volume-handle"), 1)
	barrier := &fakeCleanupBarrier{}
	if _, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, fakeProbeObserver{observation: validProbeObservationFixture()}, &fakeBackendObserver{clock: clock}, barrier, request, baseline, archive, clock); err == nil {
		t.Fatal("shared source/target provider handle unexpectedly passed")
	}
	if barrier.calls != 0 || reader.deleted {
		t.Fatalf("shared source/target backend reached cleanup: barrier=%d deleted=%t", barrier.calls, reader.deleted)
	}
}

func TestCollectorRequiresSourceBackendAfterTargetCleanup(t *testing.T) {
	t.Parallel()
	reader, archive, request, baseline, clock := preparedCollectionFixture(t)
	provider := &fakeBackendObserver{clock: clock, sourceAbsent: true}
	if _, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, fakeProbeObserver{observation: validProbeObservationFixture()}, provider, &fakeCleanupBarrier{}, request, baseline, archive, clock); err == nil || !strings.Contains(err.Error(), "source provider artifact continuity") {
		t.Fatalf("missing source backend error = %v", err)
	}
}

func TestCollectorRejectsInvalidVeleroRuntimeAndBaselineTimeline(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*testing.T, *fakeReader, *CollectionRequest, *restoreproof.SourceBaseline)
	}{
		{name: "wrong server version", mutate: func(t *testing.T, reader *fakeReader, _ *CollectionRequest, _ *restoreproof.SourceBaseline) {
			mutateObject(t, reader, restoreproof.VeleroV1ServerStatusRequestGVR, "velero", "cloudring-status", func(object map[string]any) {
				object["status"].(map[string]any)["serverVersion"] = "v1.18.1"
			})
		}},
		{name: "stale server status", mutate: func(t *testing.T, reader *fakeReader, _ *CollectionRequest, _ *restoreproof.SourceBaseline) {
			mutateObject(t, reader, restoreproof.VeleroV1ServerStatusRequestGVR, "velero", "cloudring-status", func(object map[string]any) {
				object["status"].(map[string]any)["processedTimestamp"] = "2026-07-14T12:00:00Z"
			})
		}},
		{name: "server status processed at restore completion", mutate: func(t *testing.T, reader *fakeReader, _ *CollectionRequest, _ *restoreproof.SourceBaseline) {
			mutateObject(t, reader, restoreproof.VeleroV1ServerStatusRequestGVR, "velero", "cloudring-status", func(object map[string]any) {
				object["status"].(map[string]any)["processedTimestamp"] = "2026-07-14T12:02:00Z"
			})
		}},
		{name: "wrong server status uid", mutate: func(_ *testing.T, _ *fakeReader, request *CollectionRequest, _ *restoreproof.SourceBaseline) {
			request.ServerStatusRequestUIDSHA256 = digest("other-uid")
		}},
		{name: "baseline after restore start", mutate: func(_ *testing.T, _ *fakeReader, _ *CollectionRequest, baseline *restoreproof.SourceBaseline) {
			baseline.CapturedAt = "2026-07-14T12:01:30Z"
			baseline.EvidenceSHA256 = restoreproof.SourceBaselineEvidenceSHA256(*baseline)
		}},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			reader, archive, request, baseline, clock := preparedCollectionFixture(t)
			test.mutate(t, reader, &request, &baseline)
			if _, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, fakeProbeObserver{observation: validProbeObservationFixture()}, &fakeBackendObserver{clock: clock}, &fakeCleanupBarrier{}, request, baseline, archive, clock); err == nil {
				t.Fatal("invalid runtime or baseline unexpectedly produced a receipt")
			}
		})
	}
}

func TestCollectorEnforcesExactVelero118Derivations(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		mutate      func(*testing.T, *fakeReader, []byte) []byte
		wantMessage string
	}{
		{name: "data upload timeout", mutate: mutateDataUpload(func(object map[string]any) { object["spec"].(map[string]any)["operationTimeout"] = "9m" })},
		{name: "data download timeout", mutate: func(t *testing.T, reader *fakeReader, archive []byte) []byte {
			mutateListedObject(t, reader, restoreproof.DataDownloadGVR, "velero", "restore-copy-volume", "velero.io/v2alpha1", "DataDownloadList", "51", func(object map[string]any) {
				object["spec"].(map[string]any)["operationTimeout"] = "9m"
			})
			return archive
		}},
		{name: "backup uploader config", mutate: func(t *testing.T, reader *fakeReader, archive []byte) []byte {
			mutateObject(t, reader, restoreproof.VeleroV1BackupGVR, "velero", "backup-direct", func(object map[string]any) {
				object["spec"].(map[string]any)["uploaderConfig"] = map[string]any{"parallelFilesUpload": 2}
			})
			return archive
		}},
		{name: "restore uploader config", mutate: func(t *testing.T, reader *fakeReader, archive []byte) []byte {
			mutateObject(t, reader, restoreproof.VeleroV1RestoreGVR, "velero", "restore-copy", func(object map[string]any) {
				object["spec"].(map[string]any)["uploaderConfig"] = map[string]any{"writeSparseFiles": true, "parallelFilesDownload": 2}
			})
			return archive
		}},
		{name: "source storage class", mutate: mutateDataUpload(func(object map[string]any) {
			object["spec"].(map[string]any)["csiSnapshot"].(map[string]any)["storageClass"] = "other"
		})},
		{name: "empty upload operation id", mutate: mutateDataUpload(func(object map[string]any) {
			object["metadata"].(map[string]any)["labels"].(map[string]any)["velero.io/async-operation-id"] = ""
		})},
		{name: "empty volume snapshot", mutate: mutateDataUpload(func(object map[string]any) {
			object["spec"].(map[string]any)["csiSnapshot"].(map[string]any)["volumeSnapshot"] = ""
		})},
		{name: "data upload result prefix", mutate: func(t *testing.T, reader *fakeReader, archive []byte) []byte {
			mutateObservedDataUploadResult(t, reader, func(object map[string]any) {
				object["metadata"].(map[string]any)["name"] = "unrelated-result"
			})
			return archive
		}},
		{name: "upload completed after backup", mutate: mutateDataUpload(func(object map[string]any) {
			object["status"].(map[string]any)["completionTimestamp"] = "2026-07-14T12:00:00Z"
		})},
		{name: "upload starts at completion", mutate: mutateDataUpload(func(object map[string]any) {
			object["status"].(map[string]any)["startTimestamp"] = "2026-07-14T11:58:00Z"
		})},
		{name: "backup completes after restore starts", mutate: func(t *testing.T, reader *fakeReader, archive []byte) []byte {
			mutateObject(t, reader, restoreproof.VeleroV1BackupGVR, "velero", "backup-direct", func(object map[string]any) {
				object["status"].(map[string]any)["completionTimestamp"] = "2026-07-14T12:01:01Z"
			})
			return archive
		}},
		{name: "download starts before restore", mutate: func(t *testing.T, reader *fakeReader, archive []byte) []byte {
			mutateListedObject(t, reader, restoreproof.DataDownloadGVR, "velero", "restore-copy-volume", "velero.io/v2alpha1", "DataDownloadList", "51", func(object map[string]any) {
				object["status"].(map[string]any)["startTimestamp"] = "2026-07-14T12:00:59Z"
			})
			return archive
		}},
		{name: "download completes after restore", mutate: func(t *testing.T, reader *fakeReader, archive []byte) []byte {
			mutateListedObject(t, reader, restoreproof.DataDownloadGVR, "velero", "restore-copy-volume", "velero.io/v2alpha1", "DataDownloadList", "51", func(object map[string]any) {
				object["status"].(map[string]any)["completionTimestamp"] = "2026-07-14T12:02:01Z"
			})
			return archive
		}},
		{name: "schema-invalid CSI driver", wantMessage: "restored PV lineage", mutate: func(t *testing.T, reader *fakeReader, archive []byte) []byte {
			archive = mutateDataUpload(func(object map[string]any) {
				object["spec"].(map[string]any)["csiSnapshot"].(map[string]any)["driver"] = "-invalid"
			})(t, reader, archive)
			mutateObject(t, reader, restoreproof.CoreV1PVGVR, "", "target-pv", func(object map[string]any) {
				object["spec"].(map[string]any)["csi"].(map[string]any)["driver"] = "-invalid"
			})
			return archive
		}},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			reader, archive, request, baseline, clock := preparedCollectionFixture(t)
			archive = test.mutate(t, reader, archive)
			barrier := &fakeCleanupBarrier{}
			_, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, fakeProbeObserver{observation: validProbeObservationFixture()}, &fakeBackendObserver{clock: clock}, barrier, request, baseline, archive, clock)
			wantMessage := test.wantMessage
			if wantMessage == "" {
				wantMessage = "object lineage"
			}
			if err == nil || !strings.Contains(err.Error(), wantMessage) {
				t.Fatalf("invalid Velero derivation error = %v", err)
			}
			if barrier.calls != 0 || reader.deleted {
				t.Fatalf("invalid immutable lineage reached cleanup: barrier=%d deleted=%t", barrier.calls, reader.deleted)
			}
		})
	}
}

func TestCollectorAcceptsTerminatingTargetsAndRejectsPostAbsenceRecreation(t *testing.T) {
	t.Parallel()
	t.Run("terminating then absent", func(t *testing.T) {
		reader, archive, request, baseline, clock := preparedCollectionFixture(t)
		reader.terminatingTargetOnce = true
		if _, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, fakeProbeObserver{observation: validProbeObservationFixture()}, &fakeBackendObserver{clock: clock}, &fakeCleanupBarrier{}, request, baseline, archive, clock); err != nil {
			t.Fatalf("terminating target should remain present until exact absence: %v", err)
		}
	})
	t.Run("recreated after second absence", func(t *testing.T) {
		reader, archive, request, baseline, clock := preparedCollectionFixture(t)
		provider := &fakeBackendObserver{clock: clock, onCall: func(call int) {
			if call == 3 {
				reader.replaceTargetOnCleanup = true
			}
		}}
		if _, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, fakeProbeObserver{observation: validProbeObservationFixture()}, provider, &fakeCleanupBarrier{}, request, baseline, archive, clock); err == nil || !strings.Contains(err.Error(), "final Kubernetes cleanup fence") {
			t.Fatalf("post-absence recreation error = %v", err)
		}
	})
}

func TestCleanupBarrierFailureIsFailClosedBeforeCleanupPolling(t *testing.T) {
	t.Parallel()
	reader, archive, request, baseline, clock := preparedCollectionFixture(t)
	provider := &fakeBackendObserver{clock: clock}
	readsAtBarrier := 0
	barrier := &fakeCleanupBarrier{onReady: func(CleanupReady) error {
		readsAtBarrier = reader.getCalls
		return errors.New("synthetic barrier failure")
	}}
	_, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, fakeProbeObserver{observation: validProbeObservationFixture()}, provider, barrier, request, baseline, archive, clock)
	if err == nil || !strings.Contains(err.Error(), "cleanup readiness barrier") {
		t.Fatalf("barrier failure = %v", err)
	}
	if barrier.calls != 1 || provider.calls != 1 || reader.getCalls != readsAtBarrier || clock.waits != 0 {
		t.Fatalf("failure was not before cleanup: barrier=%d provider=%d reads=%d/%d waits=%d", barrier.calls, provider.calls, reader.getCalls, readsAtBarrier, clock.waits)
	}
}

func TestCleanupBarrierRejectsPreMarkerStateDrift(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*testing.T, *fakeReader)
	}{
		{name: "target replacement", mutate: func(t *testing.T, reader *fakeReader) {
			reader.objects[readerKey(restoreproof.CoreV1PVCGVR, "target", "volume")] = kubeObject(t, "v1", "PersistentVolumeClaim", metadata("volume", "target", "replacement-uid", "99", nil, nil), map[string]any{"volumeName": "target-pv"}, nil, nil)
		}},
		{name: "same-UID ConfigMap mutation", mutate: func(t *testing.T, reader *fakeReader) {
			reader.autoDeletedResult = false
			mutateObject(t, reader, restoreproof.CoreV1CMGVR, "velero", "backup-volume-1-result", func(object map[string]any) {
				object["metadata"].(map[string]any)["resourceVersion"] = "60"
				object["data"].(map[string]any)["restore-uid"] = `{"changed":true}`
			})
		}},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			reader, archive, request, baseline, clock := preparedCollectionFixture(t)
			probe := fakeProbeObserver{observation: validProbeObservationFixture(), onObserve: func() { test.mutate(t, reader) }}
			provider := &fakeBackendObserver{clock: clock}
			barrier := &fakeCleanupBarrier{}
			_, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, probe, provider, barrier, request, baseline, archive, clock)
			if err == nil {
				t.Fatal("pre-marker state drift unexpectedly passed")
			}
			if barrier.calls != 0 || clock.waits != 0 || reader.deleted {
				t.Fatalf("pre-marker state drift reached cleanup: barrier=%d waits=%d deleted=%t", barrier.calls, clock.waits, reader.deleted)
			}
		})
	}
}

func TestCleanupBarrierRejectsStateDriftDuringProviderObservation(t *testing.T) {
	t.Parallel()
	reader, archive, request, baseline, clock := preparedCollectionFixture(t)
	provider := &fakeBackendObserver{clock: clock, onCall: func(call int) {
		if call == 1 {
			reader.autoDeletedResult = false
			mutateObject(t, reader, restoreproof.CoreV1CMGVR, "velero", "backup-volume-1-result", func(object map[string]any) {
				object["metadata"].(map[string]any)["resourceVersion"] = "61"
			})
		}
	}}
	barrier := &fakeCleanupBarrier{}
	if _, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, fakeProbeObserver{observation: validProbeObservationFixture()}, provider, barrier, request, baseline, archive, clock); err == nil {
		t.Fatal("state drift during provider observation unexpectedly passed")
	}
	if barrier.calls != 0 || reader.deleted {
		t.Fatalf("state drift during provider observation reached cleanup: barrier=%d deleted=%t", barrier.calls, reader.deleted)
	}
}

func TestCleanupBarrierRejectsSchemaInvalidAdapterIdentity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                  string
		probeImplementation   string
		backendImplementation string
	}{
		{name: "probe implementation", probeImplementation: "-invalid"},
		{name: "provider implementation", backendImplementation: "-invalid"},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			reader, archive, request, baseline, clock := preparedCollectionFixture(t)
			probe := validProbeObservationFixture()
			if test.probeImplementation != "" {
				probe.Implementation = test.probeImplementation
			}
			provider := &fakeBackendObserver{clock: clock, implementation: test.backendImplementation}
			barrier := &fakeCleanupBarrier{}
			if _, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, fakeProbeObserver{observation: probe}, provider, barrier, request, baseline, archive, clock); err == nil {
				t.Fatal("schema-invalid adapter identity unexpectedly passed")
			}
			if barrier.calls != 0 || reader.deleted {
				t.Fatalf("schema-invalid adapter identity reached cleanup: barrier=%d deleted=%t", barrier.calls, reader.deleted)
			}
		})
	}
}

func TestCleanupBarrierRejectsPartialDataProbe(t *testing.T) {
	t.Parallel()
	reader, archive, request, baseline, clock := preparedCollectionFixture(t)
	probe := validProbeObservationFixture()
	probe.ValidatedBytes = 1
	barrier := &fakeCleanupBarrier{}
	if _, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, fakeProbeObserver{observation: probe}, &fakeBackendObserver{clock: clock}, barrier, request, baseline, archive, clock); err == nil || !strings.Contains(err.Error(), "complete restored byte stream") {
		t.Fatalf("partial data probe error = %v", err)
	}
	if barrier.calls != 0 || reader.deleted {
		t.Fatalf("partial data probe reached cleanup: barrier=%d deleted=%t", barrier.calls, reader.deleted)
	}
}

func TestCleanupBarrierIsNotPublishedBeforePreCleanupTimelineIsValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                    string
		mutateProbe             func(*ProbeObservation)
		providerFirstObservedAt string
	}{
		{name: "probe starts before restore completion", mutateProbe: func(probe *ProbeObservation) { probe.StartedAt = "2026-07-14T12:01:59Z" }},
		{name: "probe completes after readiness", mutateProbe: func(probe *ProbeObservation) { probe.CompletedAt = "2026-07-14T12:02:10Z" }},
		{name: "provider presence predates probe completion", providerFirstObservedAt: "2026-07-14T12:02:01Z"},
		{name: "provider presence follows readiness", providerFirstObservedAt: "2026-07-14T12:02:10Z"},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			reader, archive, request, baseline, clock := preparedCollectionFixture(t)
			probe := validProbeObservationFixture()
			if test.mutateProbe != nil {
				test.mutateProbe(&probe)
			}
			provider := &fakeBackendObserver{clock: clock, firstObservedAt: test.providerFirstObservedAt}
			barrier := &fakeCleanupBarrier{}

			_, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, fakeProbeObserver{observation: probe}, provider, barrier, request, baseline, archive, clock)
			if err == nil || !strings.Contains(err.Error(), "pre-cleanup validation timeline is invalid") {
				t.Fatalf("pre-cleanup timeline error = %v", err)
			}
			if barrier.calls != 0 || provider.calls != 1 || clock.waits != 0 || reader.deleted {
				t.Fatalf("invalid timeline reached cleanup: barrier=%d provider=%d waits=%d deleted=%t", barrier.calls, provider.calls, clock.waits, reader.deleted)
			}
		})
	}
}

func TestCleanupTimeoutIsHardAndPollIsClamped(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: mustTime(t, "2026-07-14T12:00:00Z")}
	request := validCollectionRequest()
	request.CleanupTimeout = 20 * time.Millisecond
	request.PollInterval = time.Second
	target := observedTarget{GVR: restoreproof.CoreV1PVCGVR, Namespace: "target", Name: "volume", Proof: restoreproof.TargetResource{
		Resource: "persistentvolumeclaims", Namespace: "target", Name: "volume", UIDSHA256: digest("target-pvc-uid"), ResourceVersionSHA256: digest("rv"), ValidatedStateSHA256: digest("state"),
	}}
	started := time.Now()
	if _, err := waitForExactCleanup(t.Context(), blockingReader{}, []observedTarget{target}, request, clock); err == nil {
		t.Fatal("blocking cleanup read unexpectedly passed")
	}
	if time.Since(started) > time.Second {
		t.Fatal("cleanup timeout did not bound a stalled reader")
	}

	reader, _ := validRuntimeFixture(t)
	request.CleanupTimeout = 2 * time.Second
	request.PollInterval = 10 * time.Second
	if _, err := waitForExactCleanup(t.Context(), reader, []observedTarget{target}, request, clock); err == nil {
		t.Fatal("present cleanup target unexpectedly passed")
	}
	if clock.waits != 1 || clock.Now() != mustTime(t, "2026-07-14T12:00:02Z") {
		t.Fatalf("poll was not clamped to remaining timeout: waits=%d now=%s", clock.waits, clock.Now())
	}
}

func TestDecodersRejectDuplicateWrongGVKDeletionAndPaginationDrift(t *testing.T) {
	t.Parallel()
	if _, err := DecodeDataDownload([]byte(`{"apiVersion":"velero.io/v2alpha1","kind":"DataDownload","metadata":{"name":"one","name":"two"}}`)); err == nil {
		t.Fatal("duplicate field unexpectedly decoded")
	}
	wrong := kubeObject(t, "velero.io/v1", "DataDownload", metadata("dd", "velero", "uid", "1", nil, nil), map[string]any{}, map[string]any{}, nil)
	if _, err := DecodeDataDownload(wrong); err == nil {
		t.Fatal("wrong GVK unexpectedly decoded")
	}
	deleting := "2026-07-14T12:00:00Z"
	deleted := kubeObject(t, "velero.io/v2alpha1", "DataDownload", metadata("dd", "velero", "uid", "1", &deleting, nil), map[string]any{}, map[string]any{}, nil)
	if _, err := DecodeDataDownload(deleted); err == nil {
		t.Fatal("deleting object unexpectedly decoded")
	}
	reader := &paginationReader{pages: [][]byte{
		listObject(t, "velero.io/v2alpha1", "DataDownloadList", "10", "next", []json.RawMessage{json.RawMessage(validDataDownloadObject(t))}),
		listObject(t, "velero.io/v2alpha1", "DataDownloadList", "11", "", nil),
	}}
	if _, err := listAll(t.Context(), reader, restoreproof.DataDownloadGVR, "velero", "", "velero.io/v2alpha1", "DataDownloadList"); err == nil {
		t.Fatal("pagination resourceVersion drift unexpectedly passed")
	}
	for _, test := range []struct {
		name       string
		apiVersion string
		kind       string
		namespace  string
	}{
		{name: "wrong item apiVersion", apiVersion: "velero.io/v1", kind: "DataDownload", namespace: "velero"},
		{name: "wrong item kind", apiVersion: "velero.io/v2alpha1", kind: "DataUpload", namespace: "velero"},
		{name: "wrong item namespace", apiVersion: "velero.io/v2alpha1", kind: "DataDownload", namespace: "other"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			item := kubeObject(t, test.apiVersion, test.kind, metadata("one", test.namespace, "uid", "1", nil, nil), map[string]any{}, map[string]any{}, nil)
			page := listObject(t, "velero.io/v2alpha1", "DataDownloadList", "10", "", []json.RawMessage{item})
			if _, err := listAll(t.Context(), &paginationReader{pages: [][]byte{page}}, restoreproof.DataDownloadGVR, "velero", "", "velero.io/v2alpha1", "DataDownloadList"); err == nil {
				t.Fatal("wrong list item identity unexpectedly passed")
			}
		})
	}
}

func TestPaginationRejectsReplacementAndAggregateOverflow(t *testing.T) {
	t.Parallel()
	first := kubeObject(t, "velero.io/v2alpha1", "DataDownload", metadata("a", "velero", "uid-one", "1", nil, map[string]string{}), map[string]any{}, map[string]any{}, nil)
	replacement := kubeObject(t, "velero.io/v2alpha1", "DataDownload", metadata("a", "velero", "uid-two", "2", nil, map[string]string{}), map[string]any{}, map[string]any{}, nil)
	replaced := &paginationReader{pages: [][]byte{
		listObject(t, "velero.io/v2alpha1", "DataDownloadList", "10", "next", []json.RawMessage{first}),
		listObject(t, "velero.io/v2alpha1", "DataDownloadList", "10", "", []json.RawMessage{replacement}),
	}}
	if _, err := listAll(t.Context(), replaced, restoreproof.DataDownloadGVR, "velero", "", "velero.io/v2alpha1", "DataDownloadList"); err == nil {
		t.Fatal("same-name replacement across list pages unexpectedly passed")
	}

	pages := make([][]byte, 0, 3)
	for index, name := range []string{"a", "b", "c"} {
		item := map[string]any{
			"apiVersion": "velero.io/v2alpha1", "kind": "DataDownload",
			"metadata": map[string]any{"name": name, "namespace": "velero", "uid": "uid-" + name, "resourceVersion": "1"},
			"padding":  strings.Repeat("x", 6<<20),
		}
		continuation := ""
		if index < 2 {
			continuation = "page-" + name
		}
		pages = append(pages, listObject(t, "velero.io/v2alpha1", "DataDownloadList", "20", continuation, []json.RawMessage{mustJSON(t, item)}))
	}
	if _, err := listAll(t.Context(), &paginationReader{pages: pages}, restoreproof.DataDownloadGVR, "velero", "", "velero.io/v2alpha1", "DataDownloadList"); err == nil {
		t.Fatal("oversized aggregate list unexpectedly passed")
	}

	envelopePages := make([][]byte, 0, 3)
	for index, name := range []string{"one", "two", "three"} {
		continuation := ""
		if index < 2 {
			continuation = "envelope-" + name
		}
		envelopePages = append(envelopePages, mustJSON(t, map[string]any{
			"apiVersion": "velero.io/v2alpha1",
			"kind":       "DataDownloadList",
			"metadata":   map[string]any{"resourceVersion": "30", "continue": continuation},
			"items":      []any{},
			"padding":    strings.Repeat("x", 6<<20),
		}))
	}
	if _, err := listAll(t.Context(), &paginationReader{pages: envelopePages}, restoreproof.DataDownloadGVR, "velero", "", "velero.io/v2alpha1", "DataDownloadList"); err == nil {
		t.Fatal("oversized list page envelopes unexpectedly passed")
	}
}

func TestReadArchivedDataUploadRejectsUnsafeAndMismatchedArchives(t *testing.T) {
	t.Parallel()
	_, dataUpload := validRuntimeFixture(t)
	valid := makeArchive(t, []archiveEntry{
		{name: archivedDataUploadPath("velero", "backup-volume-1", false), body: dataUpload},
		{name: archivedDataUploadPath("velero", "backup-volume-1", true), body: dataUpload},
	})
	got, err := ReadArchivedDataUpload(bytes.NewReader(valid), "velero", "backup-volume-1")
	if err != nil {
		t.Fatalf("ReadArchivedDataUpload() error = %v", err)
	}
	zeroBytes(got)
	unsafe := makeArchive(t, []archiveEntry{{name: "../escape", body: []byte("x")}})
	if _, err := ReadArchivedDataUpload(bytes.NewReader(unsafe), "velero", "backup-volume-1"); err == nil {
		t.Fatal("unsafe archive path unexpectedly passed")
	}
	other := append([]byte(nil), dataUpload...)
	other = bytes.Replace(other, []byte(`"resourceVersion":"5"`), []byte(`"resourceVersion":"6"`), 1)
	mismatch := makeArchive(t, []archiveEntry{
		{name: archivedDataUploadPath("velero", "backup-volume-1", false), body: dataUpload},
		{name: archivedDataUploadPath("velero", "backup-volume-1", true), body: other},
	})
	if _, err := ReadArchivedDataUpload(bytes.NewReader(mismatch), "velero", "backup-volume-1"); err == nil {
		t.Fatal("mismatched archive copies unexpectedly passed")
	}
	wrongIdentity := bytes.ReplaceAll(dataUpload, []byte("backup-volume-1"), []byte("backup-volume-2"))
	wrongIdentityArchive := makeArchive(t, []archiveEntry{
		{name: archivedDataUploadPath("velero", "backup-volume-1", false), body: wrongIdentity},
		{name: archivedDataUploadPath("velero", "backup-volume-1", true), body: wrongIdentity},
	})
	if _, err := ReadArchivedDataUpload(bytes.NewReader(wrongIdentityArchive), "velero", "backup-volume-1"); err == nil {
		t.Fatal("selected archive path with a different DataUpload identity unexpectedly passed")
	}
}

func TestReadArchivedDataUploadSelectsExactObjectFromMultiVolumeArchive(t *testing.T) {
	t.Parallel()
	_, selected := validRuntimeFixture(t)
	other := bytes.ReplaceAll(selected, []byte("backup-volume-1"), []byte("backup-volume-2"))
	archive := makeArchive(t, []archiveEntry{
		{name: archivedDataUploadPath("velero", "backup-volume-2", false), body: other},
		{name: archivedDataUploadPath("velero", "backup-volume-1", false), body: selected},
		{name: archivedDataUploadPath("velero", "backup-volume-2", true), body: other},
		{name: archivedDataUploadPath("velero", "backup-volume-1", true), body: selected},
	})
	got, err := ReadArchivedDataUpload(bytes.NewReader(archive), "velero", "backup-volume-1")
	if err != nil {
		t.Fatalf("multi-volume archive selection failed: %v", err)
	}
	defer zeroBytes(got)
	if canonicalJSONSHA256(got) != canonicalJSONSHA256(selected) {
		t.Fatal("archive reader did not return the exact selected DataUpload")
	}
}

func TestCollectorAcceptsBoundedServerStatusClockSkew(t *testing.T) {
	t.Parallel()
	reader, _ := validRuntimeFixture(t)
	restorePayload := reader.objects[readerKey(restoreproof.VeleroV1RestoreGVR, "velero", "restore-copy")]
	restoreObject, err := DecodeRestore(restorePayload)
	if err != nil {
		t.Fatal(err)
	}
	request := validCollectionRequest()
	processedAt := mustTime(t, "2026-07-14T12:02:01Z")
	for _, test := range []struct {
		name    string
		now     time.Time
		wantErr bool
	}{
		{name: "within negative skew", now: processedAt.Add(-serverStatusAllowedFutureSkew)},
		{name: "beyond negative skew", now: processedAt.Add(-serverStatusAllowedFutureSkew - time.Nanosecond), wantErr: true},
		{name: "maximum age", now: processedAt.Add(serverStatusMaximumAge)},
		{name: "older than maximum age", now: processedAt.Add(serverStatusMaximumAge + time.Nanosecond), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := readVeleroRuntime(t.Context(), reader, request, restoreObject, &fakeClock{now: test.now})
			if (err != nil) != test.wantErr {
				t.Fatalf("readVeleroRuntime() error = %v, wantErr=%t", err, test.wantErr)
			}
		})
	}

	receiptReader, archive, collectionRequest, baseline, collectionClock := preparedCollectionFixture(t)
	receipt, err := CollectCSIDataMoverVolumeLineage(t.Context(), receiptReader, fakeProbeObserver{observation: validProbeObservationFixture()}, &fakeBackendObserver{clock: collectionClock}, &fakeCleanupBarrier{}, collectionRequest, baseline, archive, collectionClock)
	if err != nil {
		t.Fatal(err)
	}
	receipt.VeleroRuntime.ObservedAt = processedAt.Add(-serverStatusAllowedFutureSkew).Format(time.RFC3339Nano)
	receipt.VeleroRuntime.EvidenceSHA256 = restoreproof.VeleroRuntimeEvidenceSHA256(receipt.VeleroRuntime)
	receipt.ReceiptSHA256 = restoreproof.ReceiptSHA256(receipt)
	if err := restoreproof.ValidateCSIDataMoverVolumeReceipt(&receipt); err != nil {
		t.Fatalf("receipt validator rejected bounded clock skew: %v", err)
	}
	receipt.VeleroRuntime.ObservedAt = processedAt.Add(-serverStatusAllowedFutureSkew - time.Nanosecond).Format(time.RFC3339Nano)
	receipt.VeleroRuntime.EvidenceSHA256 = restoreproof.VeleroRuntimeEvidenceSHA256(receipt.VeleroRuntime)
	receipt.ReceiptSHA256 = restoreproof.ReceiptSHA256(receipt)
	if err := restoreproof.ValidateCSIDataMoverVolumeReceipt(&receipt); err == nil {
		t.Fatal("receipt validator accepted excessive negative clock skew")
	}
}

func TestCollectorAcceptsBenignMetadataAndResourceVersionChurn(t *testing.T) {
	t.Parallel()
	reader, archive, request, baseline, clock := preparedCollectionFixture(t)
	mutateObject(t, reader, restoreproof.CoreV1PVCGVR, "source", "volume", func(object map[string]any) {
		metadata := object["metadata"].(map[string]any)
		metadata["resourceVersion"] = "11"
		metadata["annotations"] = map[string]any{"controller.example/heartbeat": "new"}
	})
	probe := fakeProbeObserver{observation: ProbeObservation{}, onObserve: func() {
		mutateObject(t, reader, restoreproof.CoreV1PVCGVR, "target", "volume", func(object map[string]any) {
			metadata := object["metadata"].(map[string]any)
			metadata["resourceVersion"] = "22"
			metadata["annotations"] = map[string]any{"controller.example/heartbeat": "new"}
		})
	}}
	probe.observation = validProbeObservationFixture()
	receipt, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, probe, &fakeBackendObserver{clock: clock}, &fakeCleanupBarrier{}, request, baseline, archive, clock)
	if err != nil {
		t.Fatalf("benign object churn rejected: %v", err)
	}
	if receipt.Context.Cleanup.SourceResources[0].ResourceVersionBeforeSHA256 == receipt.Context.Cleanup.SourceResources[0].ResourceVersionAfterSHA256 {
		t.Fatal("receipt did not record the observed source resourceVersion change")
	}
}

func TestCollectorRejectsProofRelevantSameUIDChange(t *testing.T) {
	t.Parallel()
	reader, archive, request, baseline, clock := preparedCollectionFixture(t)
	probe := fakeProbeObserver{observation: validProbeObservationFixture(), onObserve: func() {
		mutateObject(t, reader, restoreproof.CoreV1PVCGVR, "target", "volume", func(object map[string]any) {
			object["metadata"].(map[string]any)["resourceVersion"] = "22"
			object["spec"].(map[string]any)["storageClassName"] = "other"
		})
	}}
	if _, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, probe, &fakeBackendObserver{clock: clock}, &fakeCleanupBarrier{}, request, baseline, archive, clock); err == nil {
		t.Fatal("proof-relevant same-UID change unexpectedly passed")
	}
}

func TestPreCleanupTimelineAcceptsNanosecondProbeDuration(t *testing.T) {
	t.Parallel()
	restoreObject := Restore{Status: RestoreStatus{CompletionTimestamp: "2026-07-14T12:02:00Z"}}
	probe := ProbeObservation{StartedAt: "2026-07-14T12:02:00.000000001Z", CompletedAt: "2026-07-14T12:02:00.001500002Z"}
	present := BackendObservation{ObservedAt: "2026-07-14T12:02:00.001500003Z"}
	ready := CleanupReady{ReadyAt: "2026-07-14T12:02:01Z"}
	if err := validatePreCleanupTimeline(restoreObject, probe, present, ready); err != nil {
		t.Fatalf("nanosecond probe timestamps rejected: %v", err)
	}
}

func TestCollectorAcceptsSubMillisecondNanosecondProbe(t *testing.T) {
	t.Parallel()
	reader, archive, request, baseline, clock := preparedCollectionFixture(t)
	probe := validProbeObservationFixture()
	probe.StartedAt = "2026-07-14T12:02:01.000000001Z"
	probe.CompletedAt = "2026-07-14T12:02:01.000000501Z"
	receipt, err := CollectCSIDataMoverVolumeLineage(t.Context(), reader, fakeProbeObserver{observation: probe}, &fakeBackendObserver{clock: clock}, &fakeCleanupBarrier{}, request, baseline, archive, clock)
	if err != nil {
		t.Fatalf("sub-millisecond nanosecond probe rejected: %v", err)
	}
	if got := receipt.Lineage.Probes[0].ObservedDurationMilliseconds; got != 1 {
		t.Fatalf("sub-millisecond receipt duration = %d, want 1", got)
	}
	assertReceiptMatchesSchema(t, receipt)
}

type fakeReader struct {
	objects                map[string][]byte
	lists                  map[string][]byte
	deleted                bool
	mutateSourceOnCleanup  bool
	replaceTargetOnCleanup bool
	terminatingTargetOnce  bool
	terminatingReturned    bool
	getCalls               int
	autoDeletedResult      bool
	observation            *DataUploadResultObservation
}

func (reader *fakeReader) Get(_ context.Context, gvr restoreproof.GVR, namespace, name string) ([]byte, error) {
	reader.getCalls++
	key := readerKey(gvr, namespace, name)
	if reader.autoDeletedResult && gvr == restoreproof.CoreV1CMGVR && namespace == "velero" && name == "backup-volume-1-result" {
		return nil, ErrNotFound
	}
	if reader.deleted && isCleanupKey(gvr, namespace, name) {
		if reader.replaceTargetOnCleanup && gvr == restoreproof.CoreV1PVCGVR {
			replaced := kubeObject(nil, "v1", "PersistentVolumeClaim", metadata(name, namespace, "replacement-uid", "99", nil, nil), map[string]any{"volumeName": "target-pv"}, nil, nil)
			return replaced, nil
		}
		if reader.terminatingTargetOnce && !reader.terminatingReturned && gvr == restoreproof.CoreV1PVCGVR {
			reader.terminatingReturned = true
			return withDeletionTimestamp(reader.objects[key]), nil
		}
		return nil, ErrNotFound
	}
	value, exists := reader.objects[key]
	if !exists {
		return nil, ErrNotFound
	}
	if reader.deleted && reader.mutateSourceOnCleanup && gvr == restoreproof.CoreV1PVCGVR && namespace == "source" {
		mutated := bytes.Replace(value, []byte(`"volumeName":"source-pv"`), []byte(`"volumeName":"changed-source-pv"`), 1)
		return mutated, nil
	}
	return append([]byte(nil), value...), nil
}

func (reader *fakeReader) ListPage(_ context.Context, gvr restoreproof.GVR, namespace, _, continuation string, _ int) ([]byte, error) {
	if continuation != "" {
		return nil, errors.New("unexpected continuation")
	}
	value, exists := reader.lists[readerKey(gvr, namespace, "")]
	if !exists {
		return nil, errors.New("unexpected list")
	}
	return append([]byte(nil), value...), nil
}

func (reader *fakeReader) ConfirmAbsent(_ context.Context, gvr restoreproof.GVR, namespace, name string) (bool, error) {
	if reader.autoDeletedResult && gvr == restoreproof.CoreV1CMGVR && namespace == "velero" && name == "backup-volume-1-result" {
		return true, nil
	}
	return reader.deleted && isCleanupKey(gvr, namespace, name), nil
}

type fakeClock struct {
	now         time.Time
	waits       int
	onFirstWait func()
}

func (clock *fakeClock) Now() time.Time { return clock.now }
func (clock *fakeClock) Wait(ctx context.Context, duration time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	clock.waits++
	clock.now = clock.now.Add(duration)
	if clock.waits == 1 && clock.onFirstWait != nil {
		clock.onFirstWait()
	}
	return nil
}

type fakeProbeObserver struct {
	observation ProbeObservation
	onObserve   func()
}

func (observer fakeProbeObserver) IdentitySHA256() string { return digest("fake-probe-executable") }
func (observer fakeProbeObserver) Observe(_ context.Context, request ProbeRequest) (ProbeObservation, error) {
	if observer.onObserve != nil {
		observer.onObserve()
	}
	observation := observer.observation
	observation.RequestSHA256 = adapterRequestSHA256(request)
	observation.AdapterExecutableSHA256 = observer.IdentitySHA256()
	return observation, nil
}

type fakeCleanupBarrier struct {
	calls   int
	notice  CleanupReady
	onReady func(CleanupReady) error
}

type fakePostCleanupBarrier struct {
	fakeCleanupBarrier
	postCleanupCalls int
	postCleanupError error
}

func (barrier *fakePostCleanupBarrier) ObservePostCleanup(context.Context) error {
	barrier.postCleanupCalls++
	return barrier.postCleanupError
}

func (barrier *fakeCleanupBarrier) ReadyForCleanup(_ context.Context, notice CleanupReady) error {
	barrier.calls++
	barrier.notice = notice
	if barrier.onReady != nil {
		return barrier.onReady(notice)
	}
	return nil
}

type fakeBackendObserver struct {
	clock           *fakeClock
	calls           int
	remainPresent   bool
	onCall          func(int)
	firstObservedAt string
	implementation  string
	sourceAbsent    bool
}

func (observer *fakeBackendObserver) IdentitySHA256() string {
	return digest("fake-provider-executable")
}
func (observer *fakeBackendObserver) Observe(_ context.Context, request BackendRequest) (BackendObservation, error) {
	observer.calls++
	if observer.onCall != nil {
		observer.onCall(observer.calls)
	}
	present := observer.calls == 1 || observer.remainPresent || request.ArtifactHandleSHA256 == digest("source-provider-volume-handle") && !observer.sourceAbsent
	implementation := observer.implementation
	if implementation == "" {
		implementation = "openstack-cinder"
	}
	observedAt := observer.clock.Now()
	if observer.calls == 1 && observer.firstObservedAt != "" {
		observedAt, _ = time.Parse(time.RFC3339Nano, observer.firstObservedAt)
	} else if observer.calls > 1 {
		observedAt = observedAt.Add(time.Duration(observer.calls-1) * time.Millisecond)
	}
	return BackendObservation{
		SchemaVersion: AdapterResponseSchemaVersion, Implementation: implementation, Version: "v1", Present: &present,
		RequestSHA256: adapterRequestSHA256(request), AdapterExecutableSHA256: observer.IdentitySHA256(), ArtifactHandleSHA256: request.ArtifactHandleSHA256,
		ObservedAt: observedAt.UTC().Format(time.RFC3339Nano), EvidenceRef: "runtime/task22a/provider-observation", EvidenceSHA256: digest("provider-evidence"),
	}, nil
}

type paginationReader struct {
	pages [][]byte
	index int
}

type blockingReader struct{}

func (blockingReader) Get(ctx context.Context, _ restoreproof.GVR, _, _ string) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (blockingReader) ListPage(context.Context, restoreproof.GVR, string, string, string, int) ([]byte, error) {
	return nil, errors.New("unsupported")
}
func (blockingReader) ConfirmAbsent(context.Context, restoreproof.GVR, string, string) (bool, error) {
	return false, errors.New("unsupported")
}

func (*paginationReader) Get(context.Context, restoreproof.GVR, string, string) ([]byte, error) {
	return nil, ErrNotFound
}
func (reader *paginationReader) ListPage(context.Context, restoreproof.GVR, string, string, string, int) ([]byte, error) {
	if reader.index >= len(reader.pages) {
		return nil, errors.New("no page")
	}
	value := reader.pages[reader.index]
	reader.index++
	return value, nil
}
func (*paginationReader) ConfirmAbsent(context.Context, restoreproof.GVR, string, string) (bool, error) {
	return false, errors.New("unsupported")
}

func validRuntimeFixture(t *testing.T) (*fakeReader, []byte) {
	t.Helper()
	trueValue := true
	restoreUID := "restore-uid"
	backupUID := "backup-uid"
	sourceUID := "source-pvc-uid"
	targetUID := "target-pvc-uid"
	backup := kubeObject(t, "velero.io/v1", "Backup", metadata("backup-direct", "velero", backupUID, "2", nil, map[string]string{}), map[string]any{
		"storageLocation": "offcell", "snapshotMoveData": true, "datamover": "", "csiSnapshotTimeout": "10m",
	}, map[string]any{"phase": "Completed", "completionTimestamp": "2026-07-14T11:59:00Z", "errors": 0, "warnings": 0}, nil)
	restore := kubeObject(t, "velero.io/v1", "Restore", metadata("restore-copy", "velero", restoreUID, "3", nil, map[string]string{}), map[string]any{
		"backupName": "backup-direct", "scheduleName": "", "namespaceMapping": map[string]string{"source": "target"},
	}, map[string]any{"phase": "Completed", "startTimestamp": "2026-07-14T12:01:00Z", "completionTimestamp": "2026-07-14T12:02:00Z", "errors": 0, "warnings": 0}, nil)
	serverStatus := kubeObject(t, "velero.io/v1", "ServerStatusRequest", metadata("cloudring-status", "velero", "server-status-uid", "4", nil, map[string]string{}), map[string]any{}, map[string]any{
		"phase": "Processed", "processedTimestamp": "2026-07-14T12:02:01Z", "serverVersion": "v1.18.2",
	}, nil)
	sourcePVC := kubeObject(t, "v1", "PersistentVolumeClaim", metadata("volume", "source", sourceUID, "10", nil, map[string]string{}), map[string]any{"volumeName": "source-pv", "storageClassName": "fast"}, map[string]any{"phase": "Bound"}, nil)
	sourcePV := kubeObject(t, "v1", "PersistentVolume", metadata("source-pv", "", "source-pv-uid", "11", nil, map[string]string{}), map[string]any{
		"claimRef": map[string]any{"namespace": "source", "name": "volume", "uid": sourceUID}, "csi": map[string]any{"driver": "cinder.csi.openstack.org", "volumeHandle": "source-provider-volume-handle"},
	}, map[string]any{"phase": "Bound"}, nil)
	targetPVC := kubeObject(t, "v1", "PersistentVolumeClaim", metadata("volume", "target", targetUID, "20", nil, map[string]string{}), map[string]any{"volumeName": "target-pv", "storageClassName": "fast"}, map[string]any{"phase": "Bound"}, nil)
	targetPV := kubeObject(t, "v1", "PersistentVolume", metadata("target-pv", "", "target-pv-uid", "21", nil, map[string]string{}), map[string]any{
		"claimRef": map[string]any{"namespace": "target", "name": "volume", "uid": targetUID}, "csi": map[string]any{"driver": "cinder.csi.openstack.org", "volumeHandle": "provider-volume-handle"},
	}, map[string]any{"phase": "Bound"}, nil)
	dataUpload := kubeObject(t, "velero.io/v2alpha1", "DataUpload", metadataWithOwners("backup-volume-1", "velero", "data-upload-uid", "5", map[string]string{
		"velero.io/backup-name": "backup-direct", "velero.io/backup-uid": backupUID, "velero.io/pvc-uid": sourceUID, "velero.io/async-operation-id": "du-operation",
	}, []OwnerReference{{APIVersion: "velero.io/v1", Kind: "Backup", Name: "backup-direct", UID: backupUID, Controller: &trueValue}}), map[string]any{
		"snapshotType": "CSI", "csiSnapshot": map[string]any{"volumeSnapshot": "snapshot", "storageClass": "fast", "snapshotClass": "cinder", "driver": "cinder.csi.openstack.org"},
		"sourcePVC": "volume", "datamover": "", "backupStorageLocation": "offcell", "sourceNamespace": "source", "dataMoverConfig": map[string]string{}, "cancel": false, "operationTimeout": "10m",
	}, map[string]any{
		"phase": "Completed", "message": "", "snapshotID": "snapshot-id", "dataMoverResult": map[string]string{}, "startTimestamp": "2026-07-14T11:57:00Z",
		"completionTimestamp": "2026-07-14T11:58:00Z", "progress": map[string]any{"bytesDone": 4096, "totalBytes": 4096}, "nodeOS": "linux",
	}, nil)
	resultPayload := mustJSON(t, map[string]any{"backupStorageLocation": "offcell", "datamover": "", "snapshotID": "snapshot-id", "sourceNamespace": "source", "dataMoverResult": map[string]string{}, "nodeOS": "linux", "snapshotSize": 4096})
	resultCM := kubeObject(t, "v1", "ConfigMap", metadata("backup-volume-1-result", "velero", "result-cm-uid", "6", nil, map[string]string{
		"velero.io/restore-uid": restoreUID, "velero.io/pvc-namespace-name": "source.volume", "velero.io/resource-usage": "DataUpload",
	}), nil, nil, map[string]string{restoreUID: string(resultPayload)})
	dataDownload := kubeObject(t, "velero.io/v2alpha1", "DataDownload", metadataWithOwners("restore-copy-volume", "velero", "data-download-uid", "7", map[string]string{
		"velero.io/restore-name": "restore-copy", "velero.io/restore-uid": restoreUID, "velero.io/async-operation-id": "dd-operation",
	}, []OwnerReference{{APIVersion: "velero.io/v1", Kind: "Restore", Name: "restore-copy", UID: restoreUID, Controller: &trueValue}}), map[string]any{
		"targetVolume": map[string]any{"pvc": "volume", "pv": "", "namespace": "target"}, "backupStorageLocation": "offcell", "datamover": "", "snapshotID": "snapshot-id",
		"sourceNamespace": "source", "dataMoverConfig": map[string]string{}, "cancel": false, "operationTimeout": "10m", "nodeOS": "linux", "snapshotSize": 4096,
	}, map[string]any{"phase": "Completed", "startTimestamp": "2026-07-14T12:01:10Z", "completionTimestamp": "2026-07-14T12:01:50Z", "progress": map[string]any{"bytesDone": 4096, "totalBytes": 4096}}, nil)
	reader := &fakeReader{
		autoDeletedResult: true,
		objects: map[string][]byte{
			readerKey(restoreproof.VeleroV1RestoreGVR, "velero", "restore-copy"):                 restore,
			readerKey(restoreproof.VeleroV1BackupGVR, "velero", "backup-direct"):                 backup,
			readerKey(restoreproof.CoreV1PVCGVR, "source", "volume"):                             sourcePVC,
			readerKey(restoreproof.CoreV1PVGVR, "", "source-pv"):                                 sourcePV,
			readerKey(restoreproof.CoreV1PVCGVR, "target", "volume"):                             targetPVC,
			readerKey(restoreproof.CoreV1PVGVR, "", "target-pv"):                                 targetPV,
			readerKey(restoreproof.DataUploadGVR, "velero", "backup-volume-1"):                   dataUpload,
			readerKey(restoreproof.DataDownloadGVR, "velero", "restore-copy-volume"):             dataDownload,
			readerKey(restoreproof.CoreV1CMGVR, "velero", "backup-volume-1-result"):              resultCM,
			readerKey(restoreproof.VeleroV1ServerStatusRequestGVR, "velero", "cloudring-status"): serverStatus,
		},
		lists: map[string][]byte{
			readerKey(restoreproof.DataUploadGVR, "velero", ""):   listObject(t, "velero.io/v2alpha1", "DataUploadList", "50", "", []json.RawMessage{dataUpload}),
			readerKey(restoreproof.DataDownloadGVR, "velero", ""): listObject(t, "velero.io/v2alpha1", "DataDownloadList", "51", "", []json.RawMessage{dataDownload}),
			readerKey(restoreproof.CoreV1CMGVR, "velero", ""):     listObject(t, "v1", "ConfigMapList", "52", "", []json.RawMessage{resultCM}),
		},
	}
	return reader, dataUpload
}

func preparedCollectionFixture(t *testing.T) (*fakeReader, []byte, CollectionRequest, restoreproof.SourceBaseline, *fakeClock) {
	t.Helper()
	reader, archive := validRuntimeFixture(t)
	request := validCollectionRequest()
	reader.observation = request.DataUploadResultObservation
	clock := &fakeClock{now: mustTime(t, "2026-07-14T12:00:00Z")}
	baseline, err := BuildSourceBaseline(t.Context(), reader, baselineRequestFromCollection(request), clock)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = mustTime(t, "2026-07-14T12:02:03Z")
	clock.onFirstWait = func() { reader.deleted = true }
	return reader, archive, request, baseline, clock
}

func mutateDataUpload(mutate func(map[string]any)) func(*testing.T, *fakeReader, []byte) []byte {
	return func(t *testing.T, reader *fakeReader, _ []byte) []byte {
		return mutateListedObject(t, reader, restoreproof.DataUploadGVR, "velero", "backup-volume-1", "velero.io/v2alpha1", "DataUploadList", "50", mutate)
	}
}

func mutateObject(t *testing.T, reader *fakeReader, gvr restoreproof.GVR, namespace, name string, mutate func(map[string]any)) []byte {
	t.Helper()
	key := readerKey(gvr, namespace, name)
	value, exists := reader.objects[key]
	if !exists {
		t.Fatalf("missing fixture object %s", key)
	}
	var object map[string]any
	if err := json.Unmarshal(value, &object); err != nil {
		t.Fatal(err)
	}
	mutate(object)
	updated := mustJSON(t, object)
	reader.objects[key] = updated
	return updated
}

func mutateObservedDataUploadResult(t *testing.T, reader *fakeReader, mutate func(map[string]any)) {
	t.Helper()
	if reader.observation == nil {
		t.Fatal("missing DataUploadResult observation fixture")
	}
	var object map[string]any
	if err := json.Unmarshal(reader.observation.Object, &object); err != nil {
		t.Fatal(err)
	}
	mutate(object)
	reader.observation.Object = mustJSON(t, object)
	reader.observation.ObjectSHA256 = canonicalJSONSHA256(reader.observation.Object)
	reader.observation.EvidenceSHA256 = dataUploadResultObservationEvidenceSHA256(*reader.observation)
}

func mutateListedObject(t *testing.T, reader *fakeReader, gvr restoreproof.GVR, namespace, name, apiVersion, kind, resourceVersion string, mutate func(map[string]any)) []byte {
	t.Helper()
	oldKey := readerKey(gvr, namespace, name)
	value, exists := reader.objects[oldKey]
	if !exists {
		t.Fatalf("missing fixture object %s", oldKey)
	}
	var object map[string]any
	if err := json.Unmarshal(value, &object); err != nil {
		t.Fatal(err)
	}
	mutate(object)
	updated := mustJSON(t, object)
	updatedName, _ := object["metadata"].(map[string]any)["name"].(string)
	delete(reader.objects, oldKey)
	reader.objects[readerKey(gvr, namespace, updatedName)] = updated
	reader.lists[readerKey(gvr, namespace, "")] = listObject(t, apiVersion, kind, resourceVersion, "", []json.RawMessage{updated})
	return updated
}

func withDeletionTimestamp(value []byte) []byte {
	var object map[string]any
	if json.Unmarshal(value, &object) != nil {
		return value
	}
	metadata, ok := object["metadata"].(map[string]any)
	if !ok {
		return value
	}
	metadata["deletionTimestamp"] = "2026-07-14T12:02:03Z"
	updated, err := json.Marshal(object)
	if err != nil {
		return value
	}
	return updated
}

func validCollectionRequest() CollectionRequest {
	return CollectionRequest{
		SchemaVersion: CollectionRequestSchemaVersion, VeleroNamespace: "velero", RestoreName: "restore-copy", SourceNamespace: "source", SourcePVC: "volume",
		TargetNamespace: "target", TargetPVC: "volume", DataUploadName: "backup-volume-1", EvidencePrefix: "runtime/task22a", CleanupTimeout: time.Minute, PollInterval: time.Second,
		ServerStatusRequestName: "cloudring-status", ServerStatusRequestUIDSHA256: digest("server-status-uid"), CleanupRunNonceSHA256: digest("cleanup-run-nonce"),
		DataUploadResultObservation: validDataUploadResultObservation(),
	}
}

func validDataUploadResultObservation() *DataUploadResultObservation {
	resultMetadata := metadata("backup-volume-1-result", "velero", "result-cm-uid", "6", nil, map[string]string{
		"velero.io/restore-uid": "restore-uid", "velero.io/pvc-namespace-name": "source.volume", "velero.io/resource-usage": "DataUpload",
	})
	resultMetadata["creationTimestamp"] = "2026-07-14T12:01:30Z"
	raw := kubeObject(nil, "v1", "ConfigMap", resultMetadata, nil, nil, map[string]string{"restore-uid": string(mustJSON(nil, map[string]any{
		"backupStorageLocation": "offcell", "datamover": "", "snapshotID": "snapshot-id", "sourceNamespace": "source", "dataMoverResult": map[string]string{}, "nodeOS": "linux", "snapshotSize": 4096,
	}))})
	request := DataUploadResultObservationRequest{
		SchemaVersion:   DataUploadResultObservationRequestSchemaVersion,
		VeleroNamespace: "velero", RestoreName: "restore-copy", SourceNamespace: "source", SourcePVC: "volume",
		DataUploadName: "backup-volume-1", EvidencePrefix: "runtime/task22a",
	}
	observation := &DataUploadResultObservation{
		SchemaVersion:  DataUploadResultObservationSchemaVersion,
		WatchStartedAt: "2026-07-14T12:00:30Z",
		ObservedAt:     "2026-07-14T12:01:30Z",
		CapturedAt:     "2026-07-14T12:01:31Z",
		RequestSHA256:  requestJSONSHA256(request),
		EventType:      "ADDED",
		Object:         raw,
		ObjectSHA256:   canonicalJSONSHA256(raw),
		EvidenceRef:    "runtime/task22a/velero-data-upload-result-observation",
	}
	observation.EvidenceSHA256 = dataUploadResultObservationEvidenceSHA256(*observation)
	return observation
}

func baselineRequestFromCollection(request CollectionRequest) BaselineRequest {
	return BaselineRequest{
		SchemaVersion: BaselineRequestSchemaVersion, SourceNamespace: request.SourceNamespace,
		SourcePVC: request.SourcePVC, EvidencePrefix: request.EvidencePrefix,
	}
}

func validProbeObservationFixture() ProbeObservation {
	return ProbeObservation{
		SchemaVersion: AdapterResponseSchemaVersion, Implementation: "cloudring-volume-probe", Version: "v1", HashAlgorithm: "sha256",
		SourceSHA256: digest("tenant-data"), TargetSHA256: digest("tenant-data"), ValidatedBytes: 4096,
		StartedAt: "2026-07-14T12:02:01Z", CompletedAt: "2026-07-14T12:02:02Z", EvidenceRef: "runtime/task22a/data-probe", EvidenceSHA256: digest("probe-evidence"),
	}
}

func readerKey(gvr restoreproof.GVR, namespace, name string) string {
	return gvr.Group + "/" + gvr.Version + "/" + gvr.Resource + "/" + namespace + "/" + name
}

func isCleanupKey(gvr restoreproof.GVR, namespace, name string) bool {
	return gvr == restoreproof.CoreV1PVCGVR && namespace == "target" && name == "volume" ||
		gvr == restoreproof.CoreV1PVGVR && namespace == "" && name == "target-pv" ||
		gvr == restoreproof.DataDownloadGVR && namespace == "velero" && name == "restore-copy-volume" ||
		gvr == restoreproof.CoreV1CMGVR && namespace == "velero" && name == "backup-volume-1-result"
}

func metadata(name, namespace, uid, resourceVersion string, deletion *string, labels map[string]string) map[string]any {
	return metadataWithOwners(name, namespace, uid, resourceVersion, labels, nil, deletion)
}

func metadataWithOwners(name, namespace, uid, resourceVersion string, labels map[string]string, owners []OwnerReference, deletion ...*string) map[string]any {
	result := map[string]any{"name": name, "namespace": namespace, "uid": uid, "resourceVersion": resourceVersion, "labels": labels, "ownerReferences": owners}
	if len(deletion) != 0 && deletion[0] != nil {
		result["deletionTimestamp"] = *deletion[0]
	}
	return result
}

func kubeObject(t *testing.T, apiVersion, kind string, metadata, spec, status map[string]any, data map[string]string) []byte {
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
	return mustJSON(t, value)
}

func listObject(t *testing.T, apiVersion, kind, resourceVersion, continuation string, items []json.RawMessage) []byte {
	return mustJSON(t, map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": map[string]any{"resourceVersion": resourceVersion, "continue": continuation}, "items": items})
}

func validDataDownloadObject(t *testing.T) []byte {
	return kubeObject(t, "velero.io/v2alpha1", "DataDownload", metadata("dd", "velero", "uid", "1", nil, map[string]string{}), map[string]any{}, map[string]any{}, nil)
}

func mustJSON(t *testing.T, value any) []byte {
	if t != nil {
		t.Helper()
	}
	data, err := json.Marshal(value)
	if err != nil {
		if t == nil {
			panic(err)
		}
		t.Fatal(err)
	}
	return data
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func digest(value string) string { return restoreproof.SHA256(value) }

type archiveEntry struct {
	name     string
	body     []byte
	typeflag byte
}

func makeArchive(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		if err := tarWriter.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o600, Size: int64(len(entry.body)), Typeflag: typeflag}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(tarWriter, bytes.NewReader(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
