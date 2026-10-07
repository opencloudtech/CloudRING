// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package oneserverloss

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/opencloudtech/CloudRING/pkg/kubeidentity"
)

type fakeClock struct {
	now      time.Time
	sleeps   int
	gapSleep int
}

func (clock *fakeClock) Now() time.Time { return clock.now }

func (clock *fakeClock) Sleep(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	clock.sleeps++
	if clock.sleeps == clock.gapSleep {
		duration *= 3
	}
	clock.now = clock.now.Add(duration)
	return nil
}

type fakeReader struct {
	index                     int
	replacement               bool
	lossQuorum                int
	workloadFailure           bool
	vmNeverMigrates           bool
	clock                     *fakeClock
	sampleCost                time.Duration
	terminatingTargetNode     bool
	terminatingWorkload       bool
	terminatingVirtualMachine bool
	terminatingVMI            bool
}

func (reader *fakeReader) IdentitySHA256() string { return testDigest("kubectl") }

func (reader *fakeReader) ReadyZ(context.Context) error {
	reader.index++
	if reader.clock != nil {
		reader.clock.now = reader.clock.now.Add(reader.sampleCost)
	}
	return nil
}

func (reader *fakeReader) ListPage(_ context.Context, resource Resource, namespace, selector, continuation string, _ int) ([]byte, error) {
	if continuation != "" {
		return nil, errors.New("unexpected continuation")
	}
	state := reader.index - 1
	var items []any
	switch resource.Resource {
	case "nodes":
		for node := 1; node <= 3; node++ {
			ready := state < 3 || state >= 5 || node != 1
			if state >= 3 && state < 5 && reader.lossQuorum > 0 && node > reader.lossQuorum {
				ready = false
			}
			uid := fmt.Sprintf("node-uid-%d", node)
			if node == 1 && state >= 5 && reader.replacement {
				uid = "replacement-node-uid"
			}
			item := nodeFixture(fmt.Sprintf("node-%d", node), uid, ready)
			if node == 1 && reader.terminatingTargetNode {
				markDeleting(item)
			}
			items = append(items, item)
		}
	case "pods":
		if namespace == "kube-system" {
			for node := 1; node <= 3; node++ {
				ready := state < 3 || state >= 5 || node != 1
				if state >= 3 && state < 5 && reader.lossQuorum > 0 && node > reader.lossQuorum {
					ready = false
				}
				items = append(items, podFixture("kube-system", fmt.Sprintf("control-%d", node), fmt.Sprintf("pod-uid-%d", node), fmt.Sprintf("node-%d", node), ready,
					map[string]string{"component": strings.TrimPrefix(selector, "component=")}))
			}
		} else {
			ready := !(reader.workloadFailure && state >= 3 && state < 5)
			item := podFixture(namespace, "service-0", "service-pod-uid", "node-2", ready,
				map[string]string{"app.kubernetes.io/name": "service"})
			if reader.terminatingWorkload {
				markDeleting(item)
			}
			items = append(items, item)
		}
	default:
		return nil, errors.New("unexpected list resource")
	}
	return listFixture(resource, items), nil
}

func (reader *fakeReader) Get(_ context.Context, resource Resource, namespace, name string) ([]byte, error) {
	state := reader.index - 1
	switch resource.Resource {
	case "virtualmachines":
		ready := state != 3
		item := map[string]any{
			"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine",
			"metadata": metadataFixture(namespace, name, "vm-uid"), "status": map[string]any{"ready": ready},
		}
		if reader.terminatingVirtualMachine {
			markDeleting(item)
		}
		return objectFixture(item), nil
	case "virtualmachineinstances":
		if state == 3 {
			return nil, ErrNotFound
		}
		node := "node-1"
		if state >= 4 && !reader.vmNeverMigrates {
			node = "node-2"
		}
		item := map[string]any{
			"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachineInstance",
			"metadata": metadataFixture(namespace, name, "vmi-uid"),
			"status":   map[string]any{"phase": "Running", "nodeName": node, "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}},
		}
		if reader.terminatingVMI {
			markDeleting(item)
		}
		return objectFixture(item), nil
	default:
		return nil, errors.New("unexpected get resource")
	}
}

type fakeProbe struct {
	clock   *fakeClock
	driftAt int64
}

func (probe fakeProbe) IdentitySHA256() string { return testDigest("probe-adapter") }

func (probe fakeProbe) Observe(_ context.Context, request ProbeRequest) (ProbeResponse, error) {
	digest := testDigest("business-state")
	if request.Sequence == probe.driftAt {
		digest = testDigest("changed-business-state")
	}
	now := probe.clock.Now().UTC().Format(time.RFC3339Nano)
	return ProbeResponse{
		SchemaVersion: ProbeResponseSchemaVersion, Implementation: "postgresql-probe", Version: "v1", RequestSHA256: digestJSON(request),
		AdapterExecutableSHA256: probe.IdentitySHA256(), HashAlgorithm: "sha256", DataSHA256: digest, ValidatedBytes: 4096,
		StartedAt: now, CompletedAt: now,
	}, nil
}

type recordingBarrier struct {
	marker ReadyMarker
	err    error
}

func (barrier *recordingBarrier) ReadyForFault(_ context.Context, marker ReadyMarker) error {
	barrier.marker = marker
	return barrier.err
}

func TestObserveBuildsContinuousOfflineVerifiableReceipt(t *testing.T) {
	receipt, marker := runHappyObserver(t, &fakeReader{})
	if err := ValidateReadyMarker(marker); err != nil {
		t.Fatalf("ValidateReadyMarker: %v", err)
	}
	if err := ValidateReceipt(&receipt); err != nil {
		t.Fatalf("ValidateReceipt: %v", err)
	}
	if receipt.Baseline.ControlPlaneMemberSetSHA256 == "" || marker.ControlPlaneMemberSetSHA256 != receipt.Baseline.ControlPlaneMemberSetSHA256 {
		t.Fatalf("runtime evidence did not bind the exact baseline member set: marker=%q baseline=%q", marker.ControlPlaneMemberSetSHA256, receipt.Baseline.ControlPlaneMemberSetSHA256)
	}
	if receipt.NodeUIDHashAlgorithm != kubeidentity.NodeUIDHashAlgorithm || marker.NodeUIDHashAlgorithm != kubeidentity.NodeUIDHashAlgorithm ||
		receipt.TargetNodeUIDSHA256 != kubeidentity.NodeUIDSHA256("node-uid-1") {
		t.Fatalf("observer did not use the canonical Node UID hash contract: receipt=%q marker=%q target=%q", receipt.NodeUIDHashAlgorithm, marker.NodeUIDHashAlgorithm, receipt.TargetNodeUIDSHA256)
	}
	wantMemberSet := ControlPlaneMemberSetSHA256([]string{
		kubeidentity.NodeUIDSHA256("node-uid-1"),
		kubeidentity.NodeUIDSHA256("node-uid-2"),
		kubeidentity.NodeUIDSHA256("node-uid-3"),
	})
	if receipt.Baseline.ControlPlaneMemberSetSHA256 != wantMemberSet {
		t.Fatalf("observer member-set digest = %q, want %q", receipt.Baseline.ControlPlaneMemberSetSHA256, wantMemberSet)
	}
	for _, phase := range []PhaseEvidence{receipt.PreLoss, receipt.Recovered} {
		for _, sample := range phase.Samples {
			if sample.ControlPlaneMemberSetSHA256 != receipt.Baseline.ControlPlaneMemberSetSHA256 {
				t.Fatalf("%s sample did not bind the recovered baseline member set", phase.Phase)
			}
		}
	}
	schema, err := jsonschema.NewCompiler().Compile("../../../contracts/one-server-loss/receipt.schema.json")
	if err != nil {
		t.Fatalf("compile receipt schema: %v", err)
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil || schema.Validate(instance) != nil {
		t.Fatalf("runtime receipt does not match public schema: %v", err)
	}
	if len(receipt.PreLoss.Samples) != 3 || len(receipt.Loss.Samples) != 2 || len(receipt.Recovered.Samples) != 3 {
		t.Fatalf("phase sample counts = %d/%d/%d, want 3/2/3", len(receipt.PreLoss.Samples), len(receipt.Loss.Samples), len(receipt.Recovered.Samples))
	}
	if receipt.Loss.Samples[len(receipt.Loss.Samples)-1].VM.VMIOnTarget {
		t.Fatal("VM did not migrate away from target in loss evidence")
	}
}

func TestObserveFailsClosedForContinuityViolations(t *testing.T) {
	tests := []struct {
		name   string
		reader *fakeReader
		probe  func(*fakeClock) fakeProbe
		gap    int
	}{
		{name: "target replacement", reader: &fakeReader{replacement: true}},
		{name: "quorum loss", reader: &fakeReader{lossQuorum: 1}},
		{name: "workload loss", reader: &fakeReader{workloadFailure: true}},
		{name: "VM misses SLO", reader: &fakeReader{vmNeverMigrates: true}},
		{name: "data drift", reader: &fakeReader{}, probe: func(clock *fakeClock) fakeProbe { return fakeProbe{clock: clock, driftAt: 5} }},
		{name: "sample gap", reader: &fakeReader{}, gap: 3},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			clock := newFakeClock()
			clock.gapSleep = test.gap
			probe := fakeProbe{clock: clock}
			if test.probe != nil {
				probe = test.probe(clock)
			}
			barrier := &recordingBarrier{}
			if _, err := Observe(context.Background(), test.reader, probe, barrier, validRequest(), clock); err == nil {
				t.Fatal("Observe accepted a continuity violation")
			}
		})
	}
}

func TestObserveDoesNotMisclassifySuccessfulSampleDurationAsGap(t *testing.T) {
	clock := newFakeClock()
	reader := &fakeReader{clock: clock, sampleCost: 1500 * time.Millisecond}
	request := validRequest()
	request.FaultArrivalTimeout = "20s"
	request.RecoveryTimeout = "30s"
	request.VM.MaximumUnavailableDuration = "5s"
	barrier := &recordingBarrier{}

	receipt, err := Observe(context.Background(), reader, fakeProbe{clock: clock}, barrier, request, clock)
	if err != nil {
		t.Fatalf("slow successful samples were misclassified as an observation gap: %v", err)
	}
	if err := ValidateReceipt(&receipt); err != nil {
		t.Fatalf("offline verifier rejected slow successful samples: %v", err)
	}
	for _, phase := range []PhaseEvidence{receipt.PreLoss, receipt.Loss, receipt.Recovered} {
		for _, sample := range phase.Samples {
			if mustTimestamp(sample.ObservedAt).Sub(mustTimestamp(sample.StartedAt)) != reader.sampleCost {
				t.Fatalf("sample duration was not recorded: %#v", sample)
			}
		}
	}
}

func TestValidateReceiptRejectsTwoUnavailableServersDespiteQuorum(t *testing.T) {
	receipt, _ := runHappyObserver(t, &fakeReader{})
	receipt.Baseline.ControlPlaneNodes = 5
	receipt.Baseline.EtcdMembers = 5
	receipt.Baseline.APIServerMembers = 5
	receipt.Baseline.BaselineSHA256 = baselineDigest(receipt.Baseline)
	for phaseIndex, phase := range []*PhaseEvidence{&receipt.PreLoss, &receipt.Loss, &receipt.Recovered} {
		members := 5
		if phaseIndex == 1 {
			// Three of five is still quorum, but it proves two unavailable
			// servers and must not satisfy the one-server-loss contract.
			members = 3
		}
		for index := range phase.Samples {
			phase.Samples[index].ControlPlaneReadyNodes = members
			phase.Samples[index].EtcdReadyMembers = members
			phase.Samples[index].APIServerReadyMembers = members
			phase.Samples[index].SampleSHA256 = sampleDigest(phase.Samples[index])
		}
		phase.SamplesSHA256 = digestJSON(phase.Samples)
	}
	receipt.ReceiptSHA256 = receiptDigest(receipt)
	if err := sampleHealth(
		receipt.Loss.Samples[0], PhaseLoss, receipt.MinimumControlPlane, receipt.Baseline,
		receipt.TargetNodeUIDSHA256, 2*time.Second, mustTimestamp(receipt.Loss.StartedAt),
	); err == nil {
		t.Fatal("online observer accepted two unavailable servers with quorum")
	}
	if err := ValidateReceipt(&receipt); err == nil || !strings.Contains(err.Error(), "exact loss envelope") {
		t.Fatalf("two unavailable servers with quorum were accepted: %v", err)
	}
}

func TestTerminatingObjectsRemainDecodableAndCountAsNotReady(t *testing.T) {
	tests := []struct {
		name   string
		reader *fakeReader
		assert func(*testing.T, SampleEvidence)
	}{
		{
			name:   "target node",
			reader: &fakeReader{terminatingTargetNode: true},
			assert: func(t *testing.T, sample SampleEvidence) {
				if !sample.TargetNodePresent || sample.TargetNodeReady || sample.ControlPlaneReadyNodes != 2 {
					t.Fatalf("terminating node was not counted as present but not ready: %#v", sample)
				}
			},
		},
		{
			name:   "workload pod",
			reader: &fakeReader{terminatingWorkload: true},
			assert: func(t *testing.T, sample SampleEvidence) {
				if len(sample.Workloads) != 1 || sample.Workloads[0].ReadyPods != 0 || sample.Workloads[0].DistinctReadyNodes != 0 {
					t.Fatalf("terminating workload Pod was counted ready: %#v", sample.Workloads)
				}
			},
		},
		{
			name:   "virtual machine",
			reader: &fakeReader{terminatingVirtualMachine: true},
			assert: func(t *testing.T, sample SampleEvidence) {
				if sample.VM.VMReady {
					t.Fatalf("terminating VirtualMachine was counted ready: %#v", sample.VM)
				}
			},
		},
		{
			name:   "virtual machine instance",
			reader: &fakeReader{terminatingVMI: true},
			assert: func(t *testing.T, sample SampleEvidence) {
				if sample.VM.VMIReady || sample.VM.VMIUIDSHA256 != "" || sample.VM.VMIOnTarget {
					t.Fatalf("terminating VMI was not treated as absent/not ready: %#v", sample.VM)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newFakeClock()
			parsed, err := validateRequest(validRequest())
			if err != nil {
				t.Fatal(err)
			}
			collector := sampler{
				reader: test.reader, probe: fakeProbe{clock: clock}, request: validRequest(), parsed: parsed, clock: clock,
			}
			sample, err := collector.next(context.Background(), PhasePreLoss)
			if err != nil {
				t.Fatalf("terminating object aborted sampling: %v", err)
			}
			test.assert(t, sample)
		})
	}
}

func TestListDecoderRejectsMalformedDeletionTimestamp(t *testing.T) {
	item := podFixture("service-system", "service-0", "service-pod-uid", "node-2", true,
		map[string]string{"app.kubernetes.io/name": "service"})
	item["metadata"].(map[string]any)["deletionTimestamp"] = "not-a-timestamp"
	payload := listFixture(podResource, []any{item})
	if _, err := listAll(context.Background(), fuzzListReader{payload: payload}, podResource, "service-system", ""); err == nil {
		t.Fatal("malformed deletionTimestamp passed strict list decoding")
	}
}

func TestListDecoderAcceptsDeletingPodForNotReadyAccounting(t *testing.T) {
	item := podFixture("service-system", "service-0", "service-pod-uid", "node-2", true,
		map[string]string{"app.kubernetes.io/name": "service"})
	markDeleting(item)
	payload := listFixture(podResource, []any{item})
	items, err := listAll(context.Background(), fuzzListReader{payload: payload}, podResource, "service-system", "")
	if err != nil || len(items) != 1 {
		t.Fatalf("valid deleting Pod aborted list decoding: items=%d err=%v", len(items), err)
	}
	defer zeroPayloads(items)
	pod, err := decodePod(items[0], "service-system")
	if err != nil || !objectTerminating(pod.Metadata) {
		t.Fatalf("deleting Pod was not preserved for not-ready accounting: %#v, %v", pod, err)
	}
}

func TestDecodeVMIAcceptsValidDeletionTimestampAsTerminating(t *testing.T) {
	item := map[string]any{
		"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachineInstance",
		"metadata": metadataFixture("virtualization-system", "continuity-vm", "vmi-uid"),
		"status": map[string]any{
			"phase": "Running", "nodeName": "node-1",
			"conditions": []any{map[string]any{"type": "Ready", "status": "True"}},
		},
	}
	markDeleting(item)
	vmi, err := decodeVMI(objectFixture(item), "virtualization-system", "continuity-vm")
	if err != nil || !objectTerminating(vmi.Metadata) {
		t.Fatalf("valid deleting VMI failed decoding: %#v, %v", vmi, err)
	}
	item["metadata"].(map[string]any)["deletionTimestamp"] = "not-a-timestamp"
	if _, err := decodeVMI(objectFixture(item), "virtualization-system", "continuity-vm"); err == nil {
		t.Fatal("malformed VMI deletionTimestamp passed strict decoding")
	}
}

func TestObserveStopsWhenReadyMarkerCannotBePublished(t *testing.T) {
	clock := newFakeClock()
	reader := &fakeReader{}
	barrier := &recordingBarrier{err: errors.New("synthetic marker failure")}
	if _, err := Observe(context.Background(), reader, fakeProbe{clock: clock}, barrier, validRequest(), clock); err == nil {
		t.Fatal("Observe continued after marker publication failure")
	}
	if reader.index != 3 {
		t.Fatalf("reader sample count = %d, want 3 pre-fault samples", reader.index)
	}
}

func TestValidateReceiptRejectsRehashedIdentityReplacement(t *testing.T) {
	receipt, _ := runHappyObserver(t, &fakeReader{})
	replacement := testDigest("replacement")
	for index := range receipt.Recovered.Samples {
		receipt.Recovered.Samples[index].TargetNodeUIDSHA256 = replacement
		receipt.Recovered.Samples[index].SampleSHA256 = sampleDigest(receipt.Recovered.Samples[index])
	}
	receipt.Recovered.SamplesSHA256 = digestJSON(receipt.Recovered.Samples)
	receipt.ReceiptSHA256 = receiptDigest(receipt)
	if err := ValidateReceipt(&receipt); err == nil {
		t.Fatal("ValidateReceipt accepted a rehashed target-node replacement")
	}
}

func TestValidateReceiptRejectsRehashedRecoveredMemberSetReplacement(t *testing.T) {
	receipt, _ := runHappyObserver(t, &fakeReader{})
	replacementSet := ControlPlaneMemberSetSHA256([]string{
		kubeidentity.NodeUIDSHA256("node-uid-1"),
		kubeidentity.NodeUIDSHA256("node-uid-2"),
		kubeidentity.NodeUIDSHA256("replacement-node-uid"),
	})
	for index := range receipt.Recovered.Samples {
		receipt.Recovered.Samples[index].ControlPlaneMemberSetSHA256 = replacementSet
		receipt.Recovered.Samples[index].SampleSHA256 = sampleDigest(receipt.Recovered.Samples[index])
	}
	receipt.Recovered.SamplesSHA256 = digestJSON(receipt.Recovered.Samples)
	receipt.ReceiptSHA256 = receiptDigest(receipt)
	if err := ValidateReceipt(&receipt); err == nil {
		t.Fatal("ValidateReceipt accepted a rehashed recovered control-plane member-set replacement")
	}
}

func TestValidateReceiptRejectsUnknownNodeUIDHashAlgorithm(t *testing.T) {
	receipt, _ := runHappyObserver(t, &fakeReader{})
	receipt.NodeUIDHashAlgorithm = "sha256-json-string-v0"
	receipt.ReceiptSHA256 = receiptDigest(receipt)
	if err := ValidateReceipt(&receipt); err == nil {
		t.Fatal("ValidateReceipt accepted an unknown Node UID hash algorithm")
	}
}

func TestValidateReceiptRejectsRehashedTimelineAndProbeReplay(t *testing.T) {
	receipt, _ := runHappyObserver(t, &fakeReader{})
	ready := mustTimestamp(receipt.ReadyMarkerAt).Add(500 * time.Millisecond)
	receipt.ReadyMarkerAt = ready.Format(time.RFC3339Nano)
	receipt.ReceiptSHA256 = receiptDigest(receipt)
	if err := ValidateReceipt(&receipt); err == nil {
		t.Fatal("ValidateReceipt accepted a marker time not backed by a sample")
	}

	receipt, _ = runHappyObserver(t, &fakeReader{})
	receipt.PreLoss.Samples[1].DataProbe.RequestSHA256 = receipt.PreLoss.Samples[0].DataProbe.RequestSHA256
	receipt.PreLoss.Samples[1].SampleSHA256 = sampleDigest(receipt.PreLoss.Samples[1])
	receipt.PreLoss.SamplesSHA256 = digestJSON(receipt.PreLoss.Samples)
	receipt.ReceiptSHA256 = receiptDigest(receipt)
	if err := ValidateReceipt(&receipt); err == nil {
		t.Fatal("ValidateReceipt accepted a replayed data-probe response")
	}
}

func TestListDecoderZeroesRawResponseAfterCopy(t *testing.T) {
	payload := []byte(`{"apiVersion":"v1","kind":"NodeList","metadata":{"resourceVersion":"1"},"items":[{"apiVersion":"v1","kind":"Node","metadata":{"name":"node-1","uid":"uid-1","resourceVersion":"1","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`)
	items, err := listAll(context.Background(), fuzzListReader{payload: payload}, nodeResource, "", "")
	if err != nil {
		t.Fatalf("listAll: %v", err)
	}
	for index, value := range payload {
		if value != 0 {
			t.Fatalf("raw payload byte %d was not zeroed", index)
		}
	}
	if len(items) != 1 {
		t.Fatalf("copied item count = %d, want 1", len(items))
	}
	if _, err := decodeNode(items[0]); err != nil {
		t.Fatalf("decode copied Node: %v", err)
	}
	zeroPayloads(items)
}

func TestValidateRequestRejectsUnsafeOrUnboundedBindings(t *testing.T) {
	request := validRequest()
	request.Workloads[0].ID = "Private Namespace"
	if _, err := validateRequest(request); err == nil {
		t.Fatal("validateRequest accepted unsafe public evidence ID")
	}
	request = validRequest()
	request.FaultArrivalTimeout = "60m0s"
	if _, err := validateRequest(request); err == nil {
		t.Fatal("validateRequest accepted non-canonical duration")
	}
}

func runHappyObserver(t *testing.T, reader *fakeReader) (Receipt, ReadyMarker) {
	t.Helper()
	clock := newFakeClock()
	barrier := &recordingBarrier{}
	receipt, err := Observe(context.Background(), reader, fakeProbe{clock: clock}, barrier, validRequest(), clock)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	return receipt, barrier.marker
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)}
}

func validRequest() Request {
	return Request{
		SchemaVersion: RequestSchemaVersion, RunNonceSHA256: testDigest("run-nonce"), TargetNodeName: "node-1",
		PollInterval: "1s", FaultArrivalTimeout: "5s", MinimumLossWindow: "2s", RecoveryTimeout: "10s", RecoveryStabilityWindow: "2s", MinimumControlPlaneMembers: 3,
		Workloads: []WorkloadTarget{{ID: "control-workload", Namespace: "service-system", MatchLabels: map[string]string{"app.kubernetes.io/name": "service"}, MinimumReadyPods: 1, MinimumDistinctReadyNodes: 1}},
		VM:        VMTarget{ID: "continuity-vm", Namespace: "virtualization-system", Name: "continuity-vm", RequirePreLossOnTarget: true, MaximumUnavailableDuration: "2s"},
		DataProbe: DataProbeTarget{ID: "business-state", QueryRef: "canonical-business-state", MinimumValidatedBytes: 1024},
	}
}

func listFixture(resource Resource, items []any) []byte {
	return objectFixture(map[string]any{
		"apiVersion": apiVersion(resource), "kind": resource.ListKind,
		"metadata": map[string]any{"resourceVersion": "100", "continue": ""}, "items": items,
	})
}

func nodeFixture(name, uid string, ready bool) map[string]any {
	status := "False"
	if ready {
		status = "True"
	}
	return map[string]any{
		"apiVersion": "v1", "kind": "Node", "metadata": map[string]any{
			"name": name, "uid": uid, "resourceVersion": "100", "labels": map[string]string{"node-role.kubernetes.io/control-plane": ""},
		}, "status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": status}}},
	}
}

func podFixture(namespace, name, uid, node string, ready bool, labels map[string]string) map[string]any {
	status, phase := "False", "Pending"
	if ready {
		status, phase = "True", "Running"
	}
	return map[string]any{
		"apiVersion": "v1", "kind": "Pod", "metadata": metadataWithLabelsFixture(namespace, name, uid, labels), "spec": map[string]any{"nodeName": node},
		"status": map[string]any{"phase": phase, "conditions": []any{map[string]any{"type": "Ready", "status": status}}},
	}
}

func metadataFixture(namespace, name, uid string) map[string]any {
	return map[string]any{"namespace": namespace, "name": name, "uid": uid, "resourceVersion": "100"}
}

func metadataWithLabelsFixture(namespace, name, uid string, labels map[string]string) map[string]any {
	metadata := metadataFixture(namespace, name, uid)
	metadata["labels"] = labels
	return metadata
}

func markDeleting(object map[string]any) {
	object["metadata"].(map[string]any)["deletionTimestamp"] = "2026-07-19T10:00:00Z"
}

func objectFixture(value any) []byte {
	payload, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return payload
}

func testDigest(value string) string { return digestJSON(value) }
