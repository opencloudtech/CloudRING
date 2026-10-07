// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package oneserverloss

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/kubeidentity"
)

const (
	minimumPollInterval = time.Second
	maximumPollInterval = 30 * time.Second
	maximumPhaseTimeout = time.Hour
	maximumSamples      = 4096
	maximumReceiptBytes = 7 << 20
)

var (
	safeIDPattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$`)
	dnsNamePattern    = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$`)
	labelKeyPattern   = regexp.MustCompile(`^(?:[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?/)?[A-Za-z0-9](?:[-_.A-Za-z0-9]{0,61}[A-Za-z0-9])?$`)
	labelValuePattern = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[-_.A-Za-z0-9]{0,61}[A-Za-z0-9])?)?$`)
	versionPattern    = regexp.MustCompile(`^[A-Za-z0-9](?:[-+._A-Za-z0-9]{0,62})$`)
)

type parsedRequest struct {
	poll              time.Duration
	faultTimeout      time.Duration
	lossWindow        time.Duration
	recoveryTimeout   time.Duration
	recoveryStability time.Duration
	vmUnavailable     time.Duration
	requestSHA256     string
	workloadBindings  map[string]string
	vmBinding         string
	probeBinding      string
}

func validateRequest(request Request) (parsedRequest, error) {
	parsed := parsedRequest{workloadBindings: make(map[string]string)}
	if request.SchemaVersion != RequestSchemaVersion || !validSHA256(request.RunNonceSHA256) || !validDNSName(request.TargetNodeName) ||
		request.MinimumControlPlaneMembers < 3 || request.MinimumControlPlaneMembers > 99 || len(request.Workloads) == 0 || len(request.Workloads) > 32 {
		return parsed, errors.New("one-server-loss request is invalid")
	}
	var err error
	if parsed.poll, err = canonicalDuration(request.PollInterval, minimumPollInterval, maximumPollInterval); err != nil {
		return parsed, errors.New("one-server-loss poll interval is invalid")
	}
	if parsed.faultTimeout, err = canonicalDuration(request.FaultArrivalTimeout, 2*parsed.poll, maximumPhaseTimeout); err != nil {
		return parsed, errors.New("one-server-loss fault timeout is invalid")
	}
	if parsed.lossWindow, err = canonicalDuration(request.MinimumLossWindow, 2*parsed.poll, maximumPhaseTimeout); err != nil {
		return parsed, errors.New("one-server-loss loss window is invalid")
	}
	if parsed.recoveryTimeout, err = canonicalDuration(request.RecoveryTimeout, parsed.lossWindow+2*parsed.poll, maximumPhaseTimeout); err != nil {
		return parsed, errors.New("one-server-loss recovery timeout is invalid")
	}
	if parsed.recoveryStability, err = canonicalDuration(request.RecoveryStabilityWindow, 2*parsed.poll, parsed.recoveryTimeout); err != nil {
		return parsed, errors.New("one-server-loss recovery stability window is invalid")
	}
	if parsed.vmUnavailable, err = canonicalDuration(request.VM.MaximumUnavailableDuration, parsed.poll, parsed.recoveryTimeout); err != nil {
		return parsed, errors.New("one-server-loss VM timeout is invalid")
	}
	estimatedSamples := int((parsed.faultTimeout+parsed.recoveryTimeout)/parsed.poll) + 8
	estimatedSampleBytes := 2048 + len(request.Workloads)*512
	if estimatedSamples > maximumSamples || estimatedSamples*estimatedSampleBytes > maximumReceiptBytes {
		return parsed, errors.New("one-server-loss request can exceed the evidence bound")
	}
	previousID := ""
	for _, target := range request.Workloads {
		if !validSafeID(target.ID) || target.ID <= previousID || !validDNSName(target.Namespace) || len(target.MatchLabels) == 0 || len(target.MatchLabels) > 16 ||
			target.MinimumReadyPods < 1 || target.MinimumReadyPods > 10000 || target.MinimumDistinctReadyNodes < 1 || target.MinimumDistinctReadyNodes > target.MinimumReadyPods {
			return parsed, errors.New("one-server-loss workload target is invalid")
		}
		for key, value := range target.MatchLabels {
			if !labelKeyPattern.MatchString(key) || !labelValuePattern.MatchString(value) {
				return parsed, errors.New("one-server-loss workload label binding is invalid")
			}
		}
		parsed.workloadBindings[target.ID] = digestJSON(target)
		previousID = target.ID
	}
	if !validSafeID(request.VM.ID) || !validDNSName(request.VM.Namespace) || !validDNSName(request.VM.Name) || !request.VM.RequirePreLossOnTarget {
		return parsed, errors.New("one-server-loss VM target is invalid")
	}
	if !validSafeID(request.DataProbe.ID) || !validSafeID(request.DataProbe.QueryRef) || request.DataProbe.MinimumValidatedBytes < 1 {
		return parsed, errors.New("one-server-loss data probe target is invalid")
	}
	parsed.vmBinding = digestJSON(request.VM)
	parsed.probeBinding = digestJSON(request.DataProbe)
	parsed.requestSHA256 = digestJSON(request)
	return parsed, nil
}

func ValidateReadyMarker(marker ReadyMarker) error {
	if marker.SchemaVersion != ReadyMarkerSchemaVersion || marker.Status != ReadyMarkerStatus || !validSHA256(marker.RequestSHA256) ||
		!validSHA256(marker.RunNonceSHA256) || !validSHA256(marker.TargetNodeUIDSHA256) || !validSHA256(marker.KubectlExecutableSHA256) ||
		!validSHA256(marker.ProbeAdapterSHA256) || marker.BaselineControlPlaneNodes < 3 || marker.BaselineEtcdMembers < 3 || marker.BaselineAPIServerMembers < 3 ||
		canonicalTimestamp(marker.ReadyAt) == nil || !validSHA256(marker.MarkerSHA256) {
		return errors.New("one-server-loss ready marker is invalid")
	}
	if marker.NodeUIDHashAlgorithm != "" && marker.NodeUIDHashAlgorithm != kubeidentity.NodeUIDHashAlgorithm ||
		(marker.NodeUIDHashAlgorithm == "") != (marker.ControlPlaneMemberSetSHA256 == "") ||
		marker.ControlPlaneMemberSetSHA256 != "" && !validSHA256(marker.ControlPlaneMemberSetSHA256) {
		return errors.New("one-server-loss ready marker member set is invalid")
	}
	copy := marker
	copy.MarkerSHA256 = ""
	if digestJSON(copy) != marker.MarkerSHA256 {
		return errors.New("one-server-loss ready marker digest is invalid")
	}
	return nil
}

// ValidateReadyMarkerFreshness verifies the marker's offline digest contract
// and then applies caller-supplied temporal bounds. Callers must supply their
// current time so policy evaluation remains deterministic and testable.
func ValidateReadyMarkerFreshness(marker ReadyMarker, now time.Time, maximumAge, maximumFutureSkew time.Duration) error {
	if err := ValidateReadyMarker(marker); err != nil {
		return err
	}
	if now.IsZero() || maximumAge <= 0 || maximumFutureSkew < 0 {
		return errors.New("one-server-loss ready marker freshness policy is invalid")
	}
	readyAt := canonicalTimestamp(marker.ReadyAt)
	now = now.UTC()
	if readyAt.Before(now.Add(-maximumAge)) {
		return errors.New("one-server-loss ready marker is stale")
	}
	if readyAt.After(now.Add(maximumFutureSkew)) {
		return errors.New("one-server-loss ready marker is from the future")
	}
	return nil
}

// ValidateReceipt verifies the complete sanitized receipt offline. It
// recomputes every nested digest and rejects observation gaps, identity
// replacement, quorum loss, VM SLO failures, or data-probe drift.
func ValidateReceipt(receipt *Receipt) error {
	if receipt == nil || receipt.SchemaVersion != ReceiptSchemaVersion || receipt.Status != ReceiptStatus ||
		!validSHA256(receipt.RequestSHA256) || !validSHA256(receipt.RunNonceSHA256) || !validSHA256(receipt.TargetNodeUIDSHA256) ||
		!validSHA256(receipt.KubectlExecutableSHA256) || !validSHA256(receipt.ProbeAdapterSHA256) || receipt.MinimumControlPlane < 3 || receipt.MinimumControlPlane > 99 ||
		canonicalTimestamp(receipt.StartedAt) == nil || canonicalTimestamp(receipt.ReadyMarkerAt) == nil || canonicalTimestamp(receipt.CompletedAt) == nil || !validSHA256(receipt.ReceiptSHA256) {
		return errors.New("one-server-loss receipt is invalid")
	}
	if receipt.NodeUIDHashAlgorithm != "" && receipt.NodeUIDHashAlgorithm != kubeidentity.NodeUIDHashAlgorithm {
		return errors.New("one-server-loss receipt Node UID hash algorithm is invalid")
	}
	poll, err := canonicalDuration(receipt.PollInterval, minimumPollInterval, maximumPollInterval)
	if err != nil {
		return errors.New("one-server-loss receipt poll interval is invalid")
	}
	faultTimeout, err := canonicalDuration(receipt.FaultArrivalTimeout, 2*poll, maximumPhaseTimeout)
	if err != nil {
		return errors.New("one-server-loss receipt fault timeout is invalid")
	}
	lossWindow, err := canonicalDuration(receipt.MinimumLossWindow, 2*poll, maximumPhaseTimeout)
	if err != nil {
		return errors.New("one-server-loss receipt loss window is invalid")
	}
	recoveryTimeout, err := canonicalDuration(receipt.RecoveryTimeout, lossWindow+2*poll, maximumPhaseTimeout)
	if err != nil {
		return errors.New("one-server-loss receipt recovery timeout is invalid")
	}
	recoveryStability, err := canonicalDuration(receipt.RecoveryStabilityWindow, 2*poll, recoveryTimeout)
	if err != nil {
		return errors.New("one-server-loss receipt recovery stability window is invalid")
	}
	vmUnavailable, err := canonicalDuration(receipt.MaximumVMUnavailable, poll, recoveryTimeout)
	if err != nil {
		return errors.New("one-server-loss receipt VM timeout is invalid")
	}
	if err := validateBaseline(receipt.Baseline, receipt.MinimumControlPlane); err != nil {
		return err
	}
	if (receipt.NodeUIDHashAlgorithm == "") != (receipt.Baseline.ControlPlaneMemberSetSHA256 == "") {
		return errors.New("one-server-loss receipt member-set hash algorithm binding is invalid")
	}
	phases := []struct {
		evidence PhaseEvidence
		phase    string
	}{
		{receipt.PreLoss, PhasePreLoss},
		{receipt.Loss, PhaseLoss},
		{receipt.Recovered, PhaseRecovered},
	}
	var all []SampleEvidence
	for _, item := range phases {
		if err := validatePhase(item.evidence, item.phase); err != nil {
			return err
		}
		all = append(all, item.evidence.Samples...)
	}
	if len(all) < 7 || len(all) > maximumSamples {
		return errors.New("one-server-loss receipt sample count is invalid")
	}
	start := canonicalTimestamp(receipt.StartedAt)
	ready := canonicalTimestamp(receipt.ReadyMarkerAt)
	complete := canonicalTimestamp(receipt.CompletedAt)
	preStart := canonicalTimestamp(receipt.PreLoss.StartedAt)
	preComplete := canonicalTimestamp(receipt.PreLoss.CompletedAt)
	lossStart := canonicalTimestamp(receipt.Loss.StartedAt)
	lossComplete := canonicalTimestamp(receipt.Loss.CompletedAt)
	recoveryStart := canonicalTimestamp(receipt.Recovered.StartedAt)
	recoveryComplete := canonicalTimestamp(receipt.Recovered.CompletedAt)
	firstPreStarted := canonicalTimestamp(receipt.PreLoss.Samples[0].StartedAt)
	firstPreObserved := canonicalTimestamp(receipt.PreLoss.Samples[0].ObservedAt)
	firstLossObserved := canonicalTimestamp(receipt.Loss.Samples[0].ObservedAt)
	firstRecoveryObserved := canonicalTimestamp(receipt.Recovered.Samples[0].ObservedAt)
	lastRecoveryObserved := canonicalTimestamp(receipt.Recovered.Samples[len(receipt.Recovered.Samples)-1].ObservedAt)
	if firstPreStarted == nil || firstPreObserved == nil || firstLossObserved == nil || firstRecoveryObserved == nil || lastRecoveryObserved == nil {
		return errors.New("one-server-loss receipt sample timeline is invalid")
	}
	readyMatchesSample := false
	for _, sample := range receipt.PreLoss.Samples {
		if observed := canonicalTimestamp(sample.ObservedAt); observed != nil && observed.Equal(*ready) {
			readyMatchesSample = true
			break
		}
	}
	if !start.Equal(*preStart) || !preComplete.Equal(*lossStart) || !lossComplete.Equal(*recoveryStart) || !complete.Equal(*recoveryComplete) ||
		!preStart.Equal(*firstPreStarted) || !preComplete.Equal(*firstLossObserved) || !lossStart.Equal(*firstLossObserved) || !lossComplete.Equal(*firstRecoveryObserved) ||
		!recoveryStart.Equal(*firstRecoveryObserved) || !recoveryComplete.Equal(*lastRecoveryObserved) || !readyMatchesSample || ready.Before(firstPreObserved.Add(2*poll)) ||
		ready.After(*lossStart) || lossStart.Sub(*ready) > faultTimeout || lossComplete.Sub(*lossStart) < lossWindow ||
		recoveryComplete.Sub(*lossStart) > recoveryTimeout || recoveryComplete.Sub(*recoveryStart) < recoveryStability {
		return errors.New("one-server-loss receipt phase timeline is invalid")
	}
	if err := validateSampleSequence(all, poll, receipt); err != nil {
		return err
	}
	if err := validatePhaseHealth(receipt.PreLoss.Samples, PhasePreLoss, receipt, vmUnavailable); err != nil {
		return err
	}
	if err := validatePhaseHealth(receipt.Loss.Samples, PhaseLoss, receipt, vmUnavailable); err != nil {
		return err
	}
	if err := validatePhaseHealth(receipt.Recovered.Samples, PhaseRecovered, receipt, vmUnavailable); err != nil {
		return err
	}
	copy := *receipt
	copy.ReceiptSHA256 = ""
	if digestJSON(copy) != receipt.ReceiptSHA256 {
		return errors.New("one-server-loss receipt digest is invalid")
	}
	return nil
}

func validateBaseline(baseline Baseline, minimum int) error {
	if baseline.ControlPlaneNodes < minimum || baseline.ControlPlaneNodes > 10000 || baseline.EtcdMembers < 3 || baseline.EtcdMembers > 10000 ||
		baseline.APIServerMembers < 3 || baseline.APIServerMembers > 10000 || !validSHA256(baseline.VMUIDSHA256) ||
		!validSHA256(baseline.DataSHA256) || baseline.ValidatedBytes < 1 || !validSHA256(baseline.BaselineSHA256) {
		return errors.New("one-server-loss baseline is invalid")
	}
	if baseline.ControlPlaneMemberSetSHA256 != "" && !validSHA256(baseline.ControlPlaneMemberSetSHA256) {
		return errors.New("one-server-loss baseline member set is invalid")
	}
	copy := baseline
	copy.BaselineSHA256 = ""
	if digestJSON(copy) != baseline.BaselineSHA256 {
		return errors.New("one-server-loss baseline digest is invalid")
	}
	return nil
}

func validatePhase(phase PhaseEvidence, expected string) error {
	if phase.Phase != expected || len(phase.Samples) == 0 || !validSHA256(phase.SamplesSHA256) || canonicalTimestamp(phase.StartedAt) == nil || canonicalTimestamp(phase.CompletedAt) == nil {
		return errors.New("one-server-loss phase evidence is invalid")
	}
	if digestJSON(phase.Samples) != phase.SamplesSHA256 {
		return errors.New("one-server-loss phase sample digest is invalid")
	}
	return nil
}

// ControlPlaneMemberSetSHA256 returns a deterministic, order-independent,
// domain-separated digest for unique privacy-safe control-plane member UID
// hashes. It returns an empty string for malformed, duplicate, or unbounded
// input.
func ControlPlaneMemberSetSHA256(memberUIDSHA256 []string) string {
	if len(memberUIDSHA256) < 1 || len(memberUIDSHA256) > 10000 {
		return ""
	}
	canonical := append([]string(nil), memberUIDSHA256...)
	sort.Strings(canonical)
	for index, uid := range canonical {
		if !validSHA256(uid) || index > 0 && uid == canonical[index-1] {
			return ""
		}
	}
	return digestJSON(struct {
		Domain          string   `json:"domain"`
		MemberUIDSHA256 []string `json:"memberUidSha256"`
	}{Domain: controlPlaneMemberSetDomain, MemberUIDSHA256: canonical})
}

func validateSampleSequence(samples []SampleEvidence, poll time.Duration, receipt *Receipt) error {
	var previous time.Time
	var workloadShape []WorkloadEvidence
	var vmBinding, probeBinding, probeImplementation, probeVersion string
	probeRequests := make(map[string]struct{}, len(samples))
	for index, sample := range samples {
		started, observed := canonicalTimestamp(sample.StartedAt), canonicalTimestamp(sample.ObservedAt)
		if sample.Sequence != int64(index+1) || started == nil || observed == nil || observed.Before(*started) || !validSHA256(sample.SampleSHA256) {
			return errors.New("one-server-loss sample sequence is invalid")
		}
		copy := sample
		copy.SampleSHA256 = ""
		if digestJSON(copy) != sample.SampleSHA256 {
			return errors.New("one-server-loss sample digest is invalid")
		}
		if index > 0 && (started.Before(previous) || observed.Before(previous) || started.Sub(previous) > 2*poll) {
			return errors.New("one-server-loss observation gap is invalid")
		}
		previous = *observed
		if err := validateSafeSample(sample, receipt); err != nil {
			return err
		}
		if _, duplicate := probeRequests[sample.DataProbe.RequestSHA256]; duplicate {
			return errors.New("one-server-loss data-probe request was replayed")
		}
		probeRequests[sample.DataProbe.RequestSHA256] = struct{}{}
		if index == 0 {
			workloadShape = append([]WorkloadEvidence(nil), sample.Workloads...)
			vmBinding, probeBinding = sample.VM.BindingSHA256, sample.DataProbe.BindingSHA256
			probeImplementation, probeVersion = sample.DataProbe.Implementation, sample.DataProbe.Version
		} else if !sameWorkloadShape(workloadShape, sample.Workloads) || sample.VM.BindingSHA256 != vmBinding || sample.DataProbe.BindingSHA256 != probeBinding ||
			sample.DataProbe.Implementation != probeImplementation || sample.DataProbe.Version != probeVersion {
			return errors.New("one-server-loss sample binding changed")
		}
	}
	return nil
}

func validateSafeSample(sample SampleEvidence, receipt *Receipt) error {
	started, observed := canonicalTimestamp(sample.StartedAt), canonicalTimestamp(sample.ObservedAt)
	probeStarted, probeCompleted := canonicalTimestamp(sample.DataProbe.StartedAt), canonicalTimestamp(sample.DataProbe.CompletedAt)
	if sample.Phase != PhasePreLoss && sample.Phase != PhaseLoss && sample.Phase != PhaseRecovered || !sample.ReadyZPassed || len(sample.Workloads) == 0 || len(sample.Workloads) > 32 ||
		sample.TargetNodePresent && !validSHA256(sample.TargetNodeUIDSHA256) || !sample.TargetNodePresent && sample.TargetNodeUIDSHA256 != "" ||
		sample.TargetNodeReady && !sample.TargetNodePresent || sample.ControlPlaneReadyNodes < 0 || sample.ControlPlaneReadyNodes > 10000 ||
		sample.EtcdReadyMembers < 0 || sample.EtcdReadyMembers > 10000 || sample.APIServerReadyMembers < 0 || sample.APIServerReadyMembers > 10000 ||
		!validSafeID(sample.VM.ID) || !validSHA256(sample.VM.BindingSHA256) || !validSHA256(sample.VM.VMUIDSHA256) ||
		sample.VM.VMIUIDSHA256 != "" && !validSHA256(sample.VM.VMIUIDSHA256) || sample.VM.VMIReady && sample.VM.VMIUIDSHA256 == "" ||
		sample.VM.VMIOnTarget && sample.VM.VMIUIDSHA256 == "" || !validSafeID(sample.DataProbe.ID) ||
		!validSHA256(sample.DataProbe.BindingSHA256) || !versionPattern.MatchString(sample.DataProbe.Implementation) || !versionPattern.MatchString(sample.DataProbe.Version) ||
		!validSHA256(sample.DataProbe.RequestSHA256) || sample.DataProbe.AdapterExecutableSHA256 != receipt.ProbeAdapterSHA256 ||
		sample.DataProbe.HashAlgorithm != "sha256" || !validSHA256(sample.DataProbe.DataSHA256) || sample.DataProbe.ValidatedBytes < 1 ||
		started == nil || observed == nil || probeStarted == nil || probeCompleted == nil || probeCompleted.Before(*probeStarted) ||
		probeStarted.Before(*started) || probeCompleted.After(*observed) {
		return errors.New("one-server-loss sample contains invalid safe evidence")
	}
	if sample.ControlPlaneMemberSetSHA256 != "" && !validSHA256(sample.ControlPlaneMemberSetSHA256) {
		return errors.New("one-server-loss sample member set is invalid")
	}
	previousID := ""
	for _, workload := range sample.Workloads {
		if !validSafeID(workload.ID) || workload.ID <= previousID || !validSHA256(workload.BindingSHA256) || workload.ReadyPods < 0 || workload.ReadyPods > 10000 ||
			workload.DistinctReadyNodes < 0 || workload.DistinctReadyNodes > workload.ReadyPods ||
			workload.MinimumReadyPods < 1 || workload.MinimumReadyNodes < 1 || workload.MinimumReadyNodes > workload.MinimumReadyPods {
			return errors.New("one-server-loss workload evidence is invalid")
		}
		previousID = workload.ID
	}
	return nil
}

func validatePhaseHealth(samples []SampleEvidence, phase string, receipt *Receipt, vmUnavailable time.Duration) error {
	vmRecoveredOffTarget := false
	lossStarted := canonicalTimestamp(receipt.Loss.StartedAt)
	memberSetBound := receipt.Baseline.ControlPlaneMemberSetSHA256 != ""
	for _, sample := range samples {
		if sample.Phase != phase || sample.VM.VMUIDSHA256 != receipt.Baseline.VMUIDSHA256 || sample.DataProbe.DataSHA256 != receipt.Baseline.DataSHA256 ||
			sample.DataProbe.ValidatedBytes != receipt.Baseline.ValidatedBytes || memberSetBound != (sample.ControlPlaneMemberSetSHA256 != "") {
			return errors.New("one-server-loss identity or data continuity failed")
		}
		for _, workload := range sample.Workloads {
			if workload.ReadyPods < workload.MinimumReadyPods || workload.DistinctReadyNodes < workload.MinimumReadyNodes {
				return errors.New("one-server-loss workload continuity failed")
			}
		}
		switch phase {
		case PhasePreLoss:
			if !sample.TargetNodePresent || !sample.TargetNodeReady || sample.TargetNodeUIDSHA256 != receipt.TargetNodeUIDSHA256 ||
				memberSetBound && sample.ControlPlaneMemberSetSHA256 != receipt.Baseline.ControlPlaneMemberSetSHA256 ||
				sample.ControlPlaneReadyNodes < receipt.Baseline.ControlPlaneNodes || sample.EtcdReadyMembers < receipt.Baseline.EtcdMembers || sample.APIServerReadyMembers < receipt.Baseline.APIServerMembers ||
				!sample.TargetHostsEtcd || !sample.TargetHostsAPIServer || !sample.VM.VMReady || !sample.VM.VMIReady || !sample.VM.VMIOnTarget {
				return errors.New("one-server-loss pre-loss health failed")
			}
		case PhaseLoss:
			if sample.TargetNodeReady || sample.TargetNodePresent && sample.TargetNodeUIDSHA256 != receipt.TargetNodeUIDSHA256 ||
				memberSetBound && sample.ControlPlaneMemberSetSHA256 == receipt.Baseline.ControlPlaneMemberSetSHA256 ||
				sample.ControlPlaneReadyNodes != receipt.Baseline.ControlPlaneNodes-1 || sample.EtcdReadyMembers != receipt.Baseline.EtcdMembers-1 ||
				sample.APIServerReadyMembers != receipt.Baseline.APIServerMembers-1 {
				return errors.New("one-server-loss exact loss envelope failed")
			}
			if sample.VM.VMReady && sample.VM.VMIReady && !sample.VM.VMIOnTarget {
				vmRecoveredOffTarget = true
			}
			observed := canonicalTimestamp(sample.ObservedAt)
			if !vmRecoveredOffTarget && observed.Sub(*lossStarted) > vmUnavailable {
				return errors.New("one-server-loss VM continuity SLO failed")
			}
		case PhaseRecovered:
			if !sample.TargetNodePresent || !sample.TargetNodeReady || sample.TargetNodeUIDSHA256 != receipt.TargetNodeUIDSHA256 ||
				memberSetBound && sample.ControlPlaneMemberSetSHA256 != receipt.Baseline.ControlPlaneMemberSetSHA256 ||
				sample.ControlPlaneReadyNodes < receipt.Baseline.ControlPlaneNodes || sample.EtcdReadyMembers < receipt.Baseline.EtcdMembers || sample.APIServerReadyMembers < receipt.Baseline.APIServerMembers ||
				!sample.TargetHostsEtcd || !sample.TargetHostsAPIServer || !sample.VM.VMReady || !sample.VM.VMIReady {
				return errors.New("one-server-loss recovery health failed")
			}
		}
	}
	if phase == PhaseLoss {
		last := samples[len(samples)-1]
		if !vmRecoveredOffTarget || !last.VM.VMReady || !last.VM.VMIReady || last.VM.VMIOnTarget {
			return errors.New("one-server-loss VM did not recover away from failed node")
		}
	}
	return nil
}

func sameWorkloadShape(left, right []WorkloadEvidence) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].ID != right[index].ID || left[index].BindingSHA256 != right[index].BindingSHA256 ||
			left[index].MinimumReadyPods != right[index].MinimumReadyPods || left[index].MinimumReadyNodes != right[index].MinimumReadyNodes {
			return false
		}
	}
	return true
}

func canonicalDuration(value string, minimum, maximum time.Duration) (time.Duration, error) {
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < minimum || parsed > maximum || parsed.String() != value {
		return 0, errors.New("duration is invalid")
	}
	return parsed, nil
}

func canonicalTimestamp(value string) *time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return nil
	}
	return &parsed
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validSafeID(value string) bool { return safeIDPattern.MatchString(value) }

func validDNSName(value string) bool {
	if len(value) == 0 || len(value) > 253 || !dnsNamePattern.MatchString(value) || strings.Contains(value, "..") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
	}
	return true
}

func digestJSON(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func canonicalSelector(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+labels[key])
	}
	return strings.Join(parts, ",")
}
