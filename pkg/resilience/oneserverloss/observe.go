// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package oneserverloss

import (
	"context"
	"errors"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/kubeidentity"
)

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func (systemClock) Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func SystemClock() Clock { return systemClock{} }

// Observe continuously samples a healthy pre-state, publishes the atomic
// ready marker, observes an externally caused server loss, and publishes a
// receipt only after stable recovery. It never mutates Kubernetes or provider
// state.
func Observe(ctx context.Context, reader Reader, probe Probe, barrier ReadyBarrier, request Request, clock Clock) (Receipt, error) {
	parsed, err := validateRequest(request)
	if err != nil {
		return Receipt{}, err
	}
	if ctx == nil || reader == nil || probe == nil || barrier == nil || clock == nil || !validSHA256(reader.IdentitySHA256()) || !validSHA256(probe.IdentitySHA256()) {
		return Receipt{}, errors.New("one-server-loss observer dependency is invalid")
	}
	collector := sampler{reader: reader, probe: probe, request: request, parsed: parsed, clock: clock}
	first, err := collector.next(ctx, PhasePreLoss)
	if err != nil || first.Phase != PhasePreLoss {
		return Receipt{}, errors.New("one-server-loss healthy pre-state is unavailable")
	}
	baseline := Baseline{
		ControlPlaneNodes: first.ControlPlaneReadyNodes, EtcdMembers: first.EtcdReadyMembers, APIServerMembers: first.APIServerReadyMembers,
		VMUIDSHA256: first.VM.VMUIDSHA256, DataSHA256: first.DataProbe.DataSHA256, ValidatedBytes: first.DataProbe.ValidatedBytes,
		ControlPlaneMemberSetSHA256: first.ControlPlaneMemberSetSHA256,
	}
	baseline.BaselineSHA256 = baselineDigest(baseline)
	targetUIDSHA256 := first.TargetNodeUIDSHA256
	if err := sampleHealth(first, PhasePreLoss, request.MinimumControlPlaneMembers, baseline, targetUIDSHA256, parsed.vmUnavailable, time.Time{}); err != nil {
		return Receipt{}, err
	}
	preSamples := []SampleEvidence{first}
	preStabilityStarted := mustTimestamp(first.ObservedAt)
	for mustTimestamp(preSamples[len(preSamples)-1].ObservedAt).Sub(preStabilityStarted) < 2*parsed.poll {
		if err := clock.Sleep(ctx, parsed.poll); err != nil {
			return Receipt{}, errors.New("one-server-loss pre-state observation interrupted")
		}
		sample, err := collector.next(ctx, PhasePreLoss)
		if err != nil || sample.Phase != PhasePreLoss {
			return Receipt{}, errors.New("one-server-loss pre-state did not remain stable")
		}
		if err := sampleHealth(sample, PhasePreLoss, request.MinimumControlPlaneMembers, baseline, targetUIDSHA256, parsed.vmUnavailable, time.Time{}); err != nil {
			return Receipt{}, err
		}
		if observationGap(preSamples[len(preSamples)-1], sample, parsed.poll) {
			return Receipt{}, errors.New("one-server-loss pre-state observation gap")
		}
		preSamples = append(preSamples, sample)
	}
	readyAt := preSamples[len(preSamples)-1].ObservedAt
	marker := ReadyMarker{
		SchemaVersion: ReadyMarkerSchemaVersion, Status: ReadyMarkerStatus, RequestSHA256: parsed.requestSHA256, RunNonceSHA256: request.RunNonceSHA256,
		TargetNodeUIDSHA256: targetUIDSHA256, NodeUIDHashAlgorithm: kubeidentity.NodeUIDHashAlgorithm,
		KubectlExecutableSHA256: reader.IdentitySHA256(), ProbeAdapterSHA256: probe.IdentitySHA256(),
		ControlPlaneMemberSetSHA256: baseline.ControlPlaneMemberSetSHA256,
		BaselineControlPlaneNodes:   baseline.ControlPlaneNodes, BaselineEtcdMembers: baseline.EtcdMembers, BaselineAPIServerMembers: baseline.APIServerMembers,
		ReadyAt: readyAt,
	}
	marker.MarkerSHA256 = markerDigest(marker)
	if err := ValidateReadyMarker(marker); err != nil {
		return Receipt{}, err
	}
	if err := barrier.ReadyForFault(ctx, marker); err != nil {
		return Receipt{}, errors.New("publish one-server-loss ready marker")
	}
	faultDeadline := mustTimestamp(readyAt).Add(parsed.faultTimeout)
	var lossSamples []SampleEvidence
	for len(lossSamples) == 0 {
		if err := clock.Sleep(ctx, parsed.poll); err != nil {
			return Receipt{}, errors.New("one-server-loss fault observation interrupted")
		}
		sample, err := collector.next(ctx, PhasePreLoss)
		if err != nil {
			return Receipt{}, err
		}
		if observationGap(preSamples[len(preSamples)-1], sample, parsed.poll) {
			return Receipt{}, errors.New("one-server-loss fault arrival observation gap")
		}
		if sample.Phase == PhasePreLoss {
			if mustTimestamp(sample.ObservedAt).After(faultDeadline) {
				return Receipt{}, errors.New("one-server-loss fault did not arrive before timeout")
			}
			if err := sampleHealth(sample, PhasePreLoss, request.MinimumControlPlaneMembers, baseline, targetUIDSHA256, parsed.vmUnavailable, time.Time{}); err != nil {
				return Receipt{}, err
			}
			preSamples = append(preSamples, sample)
			continue
		}
		if sample.Phase != PhaseLoss || mustTimestamp(sample.ObservedAt).After(faultDeadline) {
			return Receipt{}, errors.New("one-server-loss fault transition is invalid")
		}
		lossSamples = append(lossSamples, sample)
	}
	lossStarted := mustTimestamp(lossSamples[0].ObservedAt)
	recoveryDeadline := lossStarted.Add(parsed.recoveryTimeout)
	vmRecoveredOffTarget := false
	if err := sampleHealth(lossSamples[0], PhaseLoss, request.MinimumControlPlaneMembers, baseline, targetUIDSHA256, parsed.vmUnavailable, lossStarted); err != nil {
		return Receipt{}, err
	}
	vmRecoveredOffTarget = vmReadyOffTarget(lossSamples[0])
	var recoverySamples []SampleEvidence
	for len(recoverySamples) == 0 {
		if err := clock.Sleep(ctx, parsed.poll); err != nil {
			return Receipt{}, errors.New("one-server-loss loss observation interrupted")
		}
		sample, err := collector.next(ctx, PhaseLoss)
		if err != nil {
			return Receipt{}, err
		}
		previous := lossSamples[len(lossSamples)-1]
		if observationGap(previous, sample, parsed.poll) {
			return Receipt{}, errors.New("one-server-loss loss observation gap")
		}
		observed := mustTimestamp(sample.ObservedAt)
		if observed.After(recoveryDeadline) {
			return Receipt{}, errors.New("one-server-loss recovery timed out")
		}
		if sample.Phase == PhaseLoss {
			if err := sampleHealth(sample, PhaseLoss, request.MinimumControlPlaneMembers, baseline, targetUIDSHA256, parsed.vmUnavailable, lossStarted); err != nil {
				return Receipt{}, err
			}
			if vmReadyOffTarget(sample) {
				vmRecoveredOffTarget = true
			}
			if !vmRecoveredOffTarget && observed.Sub(lossStarted) > parsed.vmUnavailable {
				return Receipt{}, errors.New("one-server-loss VM recovery exceeded SLO")
			}
			lossSamples = append(lossSamples, sample)
			continue
		}
		if sample.Phase != PhaseRecovered || observed.Sub(lossStarted) < parsed.lossWindow || !vmRecoveredOffTarget {
			return Receipt{}, errors.New("one-server-loss loss window is invalid")
		}
		if err := sampleHealth(sample, PhaseRecovered, request.MinimumControlPlaneMembers, baseline, targetUIDSHA256, parsed.vmUnavailable, lossStarted); err != nil {
			return Receipt{}, err
		}
		recoverySamples = append(recoverySamples, sample)
	}
	recoveryStarted := mustTimestamp(recoverySamples[0].ObservedAt)
	for mustTimestamp(recoverySamples[len(recoverySamples)-1].ObservedAt).Sub(recoveryStarted) < parsed.recoveryStability {
		if err := clock.Sleep(ctx, parsed.poll); err != nil {
			return Receipt{}, errors.New("one-server-loss recovery observation interrupted")
		}
		sample, err := collector.next(ctx, PhaseRecovered)
		if err != nil || sample.Phase != PhaseRecovered {
			return Receipt{}, errors.New("one-server-loss recovery did not remain stable")
		}
		if observationGap(recoverySamples[len(recoverySamples)-1], sample, parsed.poll) || mustTimestamp(sample.ObservedAt).After(recoveryDeadline) {
			return Receipt{}, errors.New("one-server-loss recovery observation gap or timeout")
		}
		if err := sampleHealth(sample, PhaseRecovered, request.MinimumControlPlaneMembers, baseline, targetUIDSHA256, parsed.vmUnavailable, lossStarted); err != nil {
			return Receipt{}, err
		}
		recoverySamples = append(recoverySamples, sample)
	}
	receipt := Receipt{
		SchemaVersion: ReceiptSchemaVersion, Status: ReceiptStatus, RequestSHA256: parsed.requestSHA256, RunNonceSHA256: request.RunNonceSHA256,
		TargetNodeUIDSHA256: targetUIDSHA256, NodeUIDHashAlgorithm: kubeidentity.NodeUIDHashAlgorithm,
		KubectlExecutableSHA256: reader.IdentitySHA256(), ProbeAdapterSHA256: probe.IdentitySHA256(),
		StartedAt: first.StartedAt, ReadyMarkerAt: readyAt, CompletedAt: recoverySamples[len(recoverySamples)-1].ObservedAt,
		PollInterval: request.PollInterval, FaultArrivalTimeout: request.FaultArrivalTimeout, MinimumLossWindow: request.MinimumLossWindow,
		RecoveryTimeout: request.RecoveryTimeout, RecoveryStabilityWindow: request.RecoveryStabilityWindow,
		MaximumVMUnavailable: request.VM.MaximumUnavailableDuration, MinimumControlPlane: request.MinimumControlPlaneMembers, Baseline: baseline,
		PreLoss:   phaseEvidence(PhasePreLoss, first.StartedAt, lossSamples[0].ObservedAt, preSamples),
		Loss:      phaseEvidence(PhaseLoss, lossSamples[0].ObservedAt, recoverySamples[0].ObservedAt, lossSamples),
		Recovered: phaseEvidence(PhaseRecovered, recoverySamples[0].ObservedAt, recoverySamples[len(recoverySamples)-1].ObservedAt, recoverySamples),
	}
	receipt.ReceiptSHA256 = receiptDigest(receipt)
	if err := ValidateReceipt(&receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func sampleHealth(sample SampleEvidence, phase string, minimumControlPlane int, baseline Baseline, targetUID string, vmUnavailable time.Duration, lossStarted time.Time) error {
	if sample.Phase != phase || !sample.ReadyZPassed || sample.VM.VMUIDSHA256 != baseline.VMUIDSHA256 || sample.DataProbe.DataSHA256 != baseline.DataSHA256 ||
		sample.DataProbe.ValidatedBytes != baseline.ValidatedBytes || sample.ControlPlaneMemberSetSHA256 == "" {
		return errors.New("one-server-loss identity or data continuity failed")
	}
	for _, workload := range sample.Workloads {
		if workload.ReadyPods < workload.MinimumReadyPods || workload.DistinctReadyNodes < workload.MinimumReadyNodes {
			return errors.New("one-server-loss workload continuity failed")
		}
	}
	switch phase {
	case PhasePreLoss:
		if !sample.TargetNodePresent || !sample.TargetNodeReady || sample.TargetNodeUIDSHA256 != targetUID || sample.ControlPlaneReadyNodes < baseline.ControlPlaneNodes ||
			sample.ControlPlaneMemberSetSHA256 != baseline.ControlPlaneMemberSetSHA256 ||
			sample.EtcdReadyMembers < baseline.EtcdMembers || sample.APIServerReadyMembers < baseline.APIServerMembers || !sample.TargetHostsEtcd || !sample.TargetHostsAPIServer ||
			!sample.VM.VMReady || !sample.VM.VMIReady || !sample.VM.VMIOnTarget || baseline.ControlPlaneNodes < minimumControlPlane || baseline.EtcdMembers < 3 || baseline.APIServerMembers < 3 {
			return errors.New("one-server-loss pre-state health failed")
		}
	case PhaseLoss:
		if sample.TargetNodeReady || sample.TargetNodePresent && sample.TargetNodeUIDSHA256 != targetUID ||
			sample.ControlPlaneMemberSetSHA256 == baseline.ControlPlaneMemberSetSHA256 ||
			sample.ControlPlaneReadyNodes != baseline.ControlPlaneNodes-1 || sample.EtcdReadyMembers != baseline.EtcdMembers-1 ||
			sample.APIServerReadyMembers != baseline.APIServerMembers-1 || !lossStarted.IsZero() && !vmReadyOffTarget(sample) && mustTimestamp(sample.ObservedAt).Sub(lossStarted) > vmUnavailable {
			return errors.New("one-server-loss loss-state health failed")
		}
	case PhaseRecovered:
		if !sample.TargetNodePresent || !sample.TargetNodeReady || sample.TargetNodeUIDSHA256 != targetUID || sample.ControlPlaneReadyNodes < baseline.ControlPlaneNodes ||
			sample.ControlPlaneMemberSetSHA256 != baseline.ControlPlaneMemberSetSHA256 ||
			sample.EtcdReadyMembers < baseline.EtcdMembers || sample.APIServerReadyMembers < baseline.APIServerMembers || !sample.TargetHostsEtcd || !sample.TargetHostsAPIServer ||
			!sample.VM.VMReady || !sample.VM.VMIReady {
			return errors.New("one-server-loss recovery-state health failed")
		}
	}
	return nil
}

func vmReadyOffTarget(sample SampleEvidence) bool {
	return sample.VM.VMReady && sample.VM.VMIReady && !sample.VM.VMIOnTarget
}

func phaseEvidence(phase, startedAt, completedAt string, samples []SampleEvidence) PhaseEvidence {
	copy := append([]SampleEvidence(nil), samples...)
	return PhaseEvidence{Phase: phase, StartedAt: startedAt, CompletedAt: completedAt, Samples: copy, SamplesSHA256: digestJSON(copy)}
}

func observationGap(previous, current SampleEvidence, poll time.Duration) bool {
	left, right := mustTimestamp(previous.ObservedAt), mustTimestamp(current.StartedAt)
	return right.Before(left) || right.Sub(left) > 2*poll
}

func baselineDigest(baseline Baseline) string {
	copy := baseline
	copy.BaselineSHA256 = ""
	return digestJSON(copy)
}

func markerDigest(marker ReadyMarker) string {
	copy := marker
	copy.MarkerSHA256 = ""
	return digestJSON(copy)
}

func receiptDigest(receipt Receipt) string {
	copy := receipt
	copy.ReceiptSHA256 = ""
	return digestJSON(copy)
}

func mustTimestamp(value string) time.Time {
	parsed := canonicalTimestamp(value)
	if parsed == nil {
		return time.Time{}
	}
	return *parsed
}
