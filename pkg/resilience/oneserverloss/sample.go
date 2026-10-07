// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package oneserverloss

import (
	"context"
	"errors"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/kubeidentity"
)

type sampler struct {
	reader   Reader
	probe    Probe
	request  Request
	parsed   parsedRequest
	clock    Clock
	sequence int64
}

func (sampler *sampler) next(ctx context.Context, phase string) (SampleEvidence, error) {
	if sampler == nil || sampler.reader == nil || sampler.probe == nil || sampler.clock == nil {
		return SampleEvidence{}, errors.New("one-server-loss sampler is invalid")
	}
	sampler.sequence++
	started := sampler.clock.Now().UTC()
	sample := SampleEvidence{Sequence: sampler.sequence, Phase: phase, StartedAt: started.Format(time.RFC3339Nano), ReadyZPassed: true}
	if err := sampler.reader.ReadyZ(ctx); err != nil {
		return SampleEvidence{}, errors.New("Kubernetes readyz failed")
	}
	nodePayloads, err := listAll(ctx, sampler.reader, nodeResource, "", "")
	if err != nil {
		return SampleEvidence{}, err
	}
	defer zeroPayloads(nodePayloads)
	controlPlaneNodes := make(map[string]struct{})
	readyNodeNames := make(map[string]struct{})
	readyControlPlaneNames := make(map[string]struct{})
	for _, raw := range nodePayloads {
		node, err := decodeNode(raw)
		if err != nil {
			return SampleEvidence{}, err
		}
		ready := !objectTerminating(node.Metadata) && conditionTrue(node.Status.Conditions, "Ready")
		_, controlPlane := node.Metadata.Labels["node-role.kubernetes.io/control-plane"]
		if ready {
			readyNodeNames[node.Metadata.Name] = struct{}{}
			if controlPlane {
				controlPlaneNodes[node.Metadata.UID] = struct{}{}
				readyControlPlaneNames[node.Metadata.Name] = struct{}{}
			}
		}
		if node.Metadata.Name == sampler.request.TargetNodeName {
			sample.TargetNodePresent = true
			sample.TargetNodeReady = ready
			sample.TargetNodeUIDSHA256 = kubeidentity.NodeUIDSHA256(node.Metadata.UID)
		}
	}
	zeroPayloads(nodePayloads)
	sample.ControlPlaneReadyNodes = len(controlPlaneNodes)
	memberUIDSHA256 := make([]string, 0, len(controlPlaneNodes))
	for uid := range controlPlaneNodes {
		memberUIDSHA256 = append(memberUIDSHA256, kubeidentity.NodeUIDSHA256(uid))
	}
	sample.ControlPlaneMemberSetSHA256 = ControlPlaneMemberSetSHA256(memberUIDSHA256)
	if sample.ControlPlaneMemberSetSHA256 == "" {
		return SampleEvidence{}, errors.New("control-plane member identity set is invalid")
	}
	if phase == PhasePreLoss && !sample.TargetNodeReady {
		sample.Phase = PhaseLoss
	} else if phase == PhaseLoss && sample.TargetNodeReady {
		sample.Phase = PhaseRecovered
	}
	if sample.EtcdReadyMembers, sample.TargetHostsEtcd, err = sampler.controlPlanePods(ctx, "etcd", readyControlPlaneNames); err != nil {
		return SampleEvidence{}, err
	}
	if sample.APIServerReadyMembers, sample.TargetHostsAPIServer, err = sampler.controlPlanePods(ctx, "kube-apiserver", readyControlPlaneNames); err != nil {
		return SampleEvidence{}, err
	}
	for _, target := range sampler.request.Workloads {
		payloads, err := listAll(ctx, sampler.reader, podResource, target.Namespace, canonicalSelector(target.MatchLabels))
		if err != nil {
			return SampleEvidence{}, err
		}
		readyPods, readyNodes := 0, make(map[string]struct{})
		workloadErr := error(nil)
		for _, raw := range payloads {
			pod, err := decodePod(raw, target.Namespace)
			if err != nil {
				workloadErr = err
				break
			}
			if !labelsMatch(pod.Metadata.Labels, target.MatchLabels) {
				workloadErr = errors.New("Kubernetes workload list violated its selector")
				break
			}
			_, nodeReady := readyNodeNames[pod.Spec.NodeName]
			if nodeReady && !objectTerminating(pod.Metadata) && pod.Status.Phase == "Running" && pod.Spec.NodeName != "" && conditionTrue(pod.Status.Conditions, "Ready") {
				readyPods++
				readyNodes[pod.Spec.NodeName] = struct{}{}
			}
		}
		zeroPayloads(payloads)
		if workloadErr != nil {
			return SampleEvidence{}, workloadErr
		}
		sample.Workloads = append(sample.Workloads, WorkloadEvidence{
			ID: target.ID, BindingSHA256: sampler.parsed.workloadBindings[target.ID], ReadyPods: readyPods, DistinctReadyNodes: len(readyNodes),
			MinimumReadyPods: target.MinimumReadyPods, MinimumReadyNodes: target.MinimumDistinctReadyNodes,
		})
	}
	vmPayload, err := sampler.reader.Get(ctx, vmResource, sampler.request.VM.Namespace, sampler.request.VM.Name)
	if err != nil {
		return SampleEvidence{}, errors.New("read exact VirtualMachine")
	}
	vm, err := decodeVM(vmPayload, sampler.request.VM.Namespace, sampler.request.VM.Name)
	zeroBytes(vmPayload)
	if err != nil {
		return SampleEvidence{}, err
	}
	sample.VM = VMEvidence{
		ID: sampler.request.VM.ID, BindingSHA256: sampler.parsed.vmBinding, VMUIDSHA256: digestJSON(vm.Metadata.UID),
		VMReady: !objectTerminating(vm.Metadata) && vm.Status.Ready,
	}
	vmiPayload, err := sampler.reader.Get(ctx, vmiResource, sampler.request.VM.Namespace, sampler.request.VM.Name)
	if err == nil {
		vmi, decodeErr := decodeVMI(vmiPayload, sampler.request.VM.Namespace, sampler.request.VM.Name)
		zeroBytes(vmiPayload)
		if decodeErr != nil {
			return SampleEvidence{}, decodeErr
		}
		if !objectTerminating(vmi.Metadata) {
			sample.VM.VMIUIDSHA256 = digestJSON(vmi.Metadata.UID)
			_, vmiNodeReady := readyNodeNames[vmi.Status.NodeName]
			sample.VM.VMIReady = vmiNodeReady && vmi.Status.Phase == "Running" && conditionTrue(vmi.Status.Conditions, "Ready")
			sample.VM.VMIOnTarget = vmi.Status.NodeName == sampler.request.TargetNodeName
		}
	} else if !errors.Is(err, ErrNotFound) {
		return SampleEvidence{}, errors.New("read exact VirtualMachineInstance")
	}
	probeRequest := ProbeRequest{
		SchemaVersion: ProbeRequestSchemaVersion, RunNonceSHA256: sampler.request.RunNonceSHA256, ParentRequestSHA256: sampler.parsed.requestSHA256,
		Phase: sample.Phase, Sequence: sample.Sequence, ProbeID: sampler.request.DataProbe.ID, QueryRef: sampler.request.DataProbe.QueryRef,
		AdapterExecutableSHA256: sampler.probe.IdentitySHA256(),
	}
	probeResponse, err := sampler.probe.Observe(ctx, probeRequest)
	if err != nil {
		return SampleEvidence{}, errors.New("data continuity probe failed")
	}
	if err := validateProbeResponse(probeRequest, probeResponse, sampler.request.DataProbe.MinimumValidatedBytes); err != nil {
		return SampleEvidence{}, err
	}
	sample.DataProbe = DataProbeEvidence{
		ID: sampler.request.DataProbe.ID, BindingSHA256: sampler.parsed.probeBinding, Implementation: probeResponse.Implementation, Version: probeResponse.Version,
		RequestSHA256: probeResponse.RequestSHA256, AdapterExecutableSHA256: probeResponse.AdapterExecutableSHA256, HashAlgorithm: probeResponse.HashAlgorithm,
		DataSHA256: probeResponse.DataSHA256, ValidatedBytes: probeResponse.ValidatedBytes, StartedAt: probeResponse.StartedAt, CompletedAt: probeResponse.CompletedAt,
	}
	sample.ObservedAt = sampler.clock.Now().UTC().Format(time.RFC3339Nano)
	sample.SampleSHA256 = sampleDigest(sample)
	return sample, nil
}

func (sampler *sampler) controlPlanePods(ctx context.Context, component string, readyControlPlaneNodes map[string]struct{}) (int, bool, error) {
	payloads, err := listAll(ctx, sampler.reader, podResource, "kube-system", "component="+component)
	if err != nil {
		return 0, false, err
	}
	nodes := make(map[string]struct{})
	target := false
	defer zeroPayloads(payloads)
	for _, raw := range payloads {
		pod, err := decodePod(raw, "kube-system")
		if err != nil {
			return 0, false, err
		}
		if pod.Metadata.Labels["component"] != component {
			return 0, false, errors.New("Kubernetes control-plane list violated its selector")
		}
		_, nodeReady := readyControlPlaneNodes[pod.Spec.NodeName]
		if !nodeReady || objectTerminating(pod.Metadata) || pod.Status.Phase != "Running" || pod.Spec.NodeName == "" || !conditionTrue(pod.Status.Conditions, "Ready") {
			continue
		}
		nodes[pod.Spec.NodeName] = struct{}{}
		if pod.Spec.NodeName == sampler.request.TargetNodeName {
			target = true
		}
	}
	return len(nodes), target, nil
}

func labelsMatch(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func validateProbeResponse(request ProbeRequest, response ProbeResponse, minimumBytes int64) error {
	started, completed := canonicalTimestamp(response.StartedAt), canonicalTimestamp(response.CompletedAt)
	if response.SchemaVersion != ProbeResponseSchemaVersion || !versionPattern.MatchString(response.Implementation) || !versionPattern.MatchString(response.Version) ||
		response.RequestSHA256 != digestJSON(request) || response.AdapterExecutableSHA256 != request.AdapterExecutableSHA256 || !validSHA256(response.AdapterExecutableSHA256) ||
		response.HashAlgorithm != "sha256" || !validSHA256(response.DataSHA256) || response.ValidatedBytes < minimumBytes || started == nil || completed == nil || completed.Before(*started) {
		return errors.New("data continuity probe response is invalid")
	}
	return nil
}

func sampleDigest(sample SampleEvidence) string {
	copy := sample
	copy.SampleSHA256 = ""
	return digestJSON(copy)
}
