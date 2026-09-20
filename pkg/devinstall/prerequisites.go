// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type Prerequisites struct {
	ObservedAt                                 time.Time `json:"observedAt"`
	TargetClusterUID                           string    `json:"targetClusterUID"`
	Node                                       string    `json:"node"`
	AvailableCPUMilli                          int64     `json:"availableCPUMilli"`
	AvailableMemoryMiB                         int64     `json:"availableMemoryMiB"`
	StorageClass                               string    `json:"storageClass"`
	StorageReclaimPolicy                       string    `json:"storageReclaimPolicy"`
	StoragePlacementRequiresOperatorAcceptance bool      `json:"storagePlacementRequiresOperatorAcceptance"`
	NetworkPolicyRequiresLiveDenialTest        bool      `json:"networkPolicyRequiresLiveDenialTest"`
}

func (client *Client) verifyCluster(ctx context.Context) error {
	object, err := client.get(ctx, Object{APIVersion: "v1", Kind: "Namespace", Resource: "namespaces", Name: "kube-system"})
	if err != nil {
		return err
	}
	meta, ok := metadata(object)
	if !ok || stringField(meta, "uid") != client.profile.Target.KubeSystemUID {
		return errors.New("development substrate cluster identity mismatch")
	}
	return nil
}

// CheckPrerequisites performs fresh read-only checks. Its report explicitly
// distinguishes API scheduling headroom from storage failure headroom and
// policy enforcement, which need the operator's substrate-specific evidence.
func (client *Client) CheckPrerequisites(ctx context.Context) (Prerequisites, error) {
	if err := client.verifyCluster(ctx); err != nil {
		return Prerequisites{}, err
	}
	profile := client.profile
	for _, name := range []string{"virtualmachines.kubevirt.io", "virtualmachineinstances.kubevirt.io", "datavolumes.cdi.kubevirt.io", "ciliumnetworkpolicies.cilium.io", "volumes.longhorn.io"} {
		object, err := client.get(ctx, Object{APIVersion: "apiextensions.k8s.io/v1", Kind: "CustomResourceDefinition", Resource: "customresourcedefinitions", Name: name})
		if err != nil {
			return Prerequisites{}, err
		}
		if !condition(object, "Established", "True") {
			return Prerequisites{}, errors.New("required development substrate API is not established")
		}
	}
	storage, err := client.get(ctx, Object{APIVersion: "storage.k8s.io/v1", Kind: "StorageClass", Resource: "storageclasses", Name: profile.Target.StorageClass})
	if err != nil {
		return Prerequisites{}, err
	}
	if stringField(storage, "reclaimPolicy") != "Delete" || stringField(storage, "provisioner") != "driver.longhorn.io" {
		return Prerequisites{}, errors.New("development storage class must use Longhorn with Delete reclaim")
	}
	if profile.Target.PriorityClass != profile.Target.Namespace {
		priority, err := client.get(ctx, Object{APIVersion: "scheduling.k8s.io/v1", Kind: "PriorityClass", Resource: "priorityclasses", Name: profile.Target.PriorityClass})
		if err != nil {
			return Prerequisites{}, err
		}
		value, ok := priority["value"].(float64)
		if !ok || value > 0 || priority["globalDefault"] == true || stringField(priority, "preemptionPolicy") != "Never" {
			return Prerequisites{}, errors.New("development priority must be nonpreempting and nonpositive")
		}
	}
	var nodes struct {
		Items []apiObject `json:"items"`
	}
	if err := client.request(ctx, http.MethodGet, "/api/v1/nodes", nil, nil, &nodes); err != nil {
		return Prerequisites{}, err
	}
	if len(nodes.Items) == 0 || len(nodes.Items) > 1000 {
		return Prerequisites{}, errors.New("development substrate node inventory is invalid")
	}
	var selected apiObject
	for _, node := range nodes.Items {
		meta, _ := metadata(node)
		if stringField(meta, "name") == profile.Target.Node {
			selected = node
		}
		spec := nested(node, "spec")
		if cidr := stringField(spec, "podCIDR"); cidr != "" && !networkSeparated(profile, cidr) {
			return Prerequisites{}, errors.New("development network overlaps substrate pod CIDR")
		}
		if cidrs, ok := spec["podCIDRs"].([]any); ok {
			for _, value := range cidrs {
				if cidr, ok := value.(string); !ok || !networkSeparated(profile, cidr) {
					return Prerequisites{}, errors.New("development network overlaps substrate pod CIDR")
				}
			}
		}
		addresses, _ := nested(node, "status")["addresses"].([]any)
		for _, item := range addresses {
			address, _ := item.(map[string]any)
			if stringField(address, "type") == "InternalIP" {
				ip, err := netip.ParseAddr(stringField(address, "address"))
				if err != nil || !networkSeparated(profile, netip.PrefixFrom(ip, ip.BitLen()).String()) {
					return Prerequisites{}, errors.New("development network contains a substrate node address")
				}
			}
		}
	}
	if selected == nil || !condition(selected, "Ready", "True") || condition(selected, "MemoryPressure", "True") ||
		condition(selected, "DiskPressure", "True") || condition(selected, "PIDPressure", "True") || nested(selected, "spec")["unschedulable"] == true ||
		stringField(nested(selected, "status", "nodeInfo"), "architecture") != "amd64" {
		return Prerequisites{}, errors.New("selected development node is not a healthy schedulable amd64 host")
	}
	if taints, ok := nested(selected, "spec")["taints"].([]any); ok {
		for _, item := range taints {
			value, _ := item.(map[string]any)
			effect := stringField(value, "effect")
			if effect == "NoSchedule" || effect == "NoExecute" {
				return Prerequisites{}, errors.New("selected development node has an untolerated scheduling taint")
			}
		}
	}
	var services struct {
		Items []apiObject `json:"items"`
	}
	if err := client.request(ctx, http.MethodGet, "/apis/networking.k8s.io/v1/servicecidrs", nil, nil, &services); err != nil {
		return Prerequisites{}, err
	}
	if len(services.Items) == 0 || len(services.Items) > 64 {
		return Prerequisites{}, errors.New("development substrate service CIDR inventory is invalid")
	}
	for _, item := range services.Items {
		cidrs, ok := nested(item, "spec")["cidrs"].([]any)
		if !ok || len(cidrs) == 0 {
			return Prerequisites{}, errors.New("development substrate service CIDR is unavailable")
		}
		for _, value := range cidrs {
			cidr, ok := value.(string)
			if !ok || !networkSeparated(profile, cidr) {
				return Prerequisites{}, errors.New("development network overlaps substrate service CIDR")
			}
		}
	}
	allocatable := nested(selected, "status", "allocatable")
	cpu, err := quantityMilli(stringField(allocatable, "cpu"))
	if err != nil {
		return Prerequisites{}, err
	}
	memory, err := quantityMilli(stringField(allocatable, "memory"))
	if err != nil {
		return Prerequisites{}, err
	}
	for _, name := range []string{"devices.kubevirt.io/kvm", "devices.kubevirt.io/tun", "devices.kubevirt.io/vhost-net"} {
		value, err := quantityMilli(stringField(allocatable, name))
		if err != nil || value < 1000 {
			return Prerequisites{}, errors.New("selected node lacks a required KVM device resource")
		}
	}
	var pods struct {
		Items []apiObject `json:"items"`
	}
	if err := client.request(ctx, http.MethodGet, "/api/v1/pods", url.Values{"fieldSelector": {"spec.nodeName=" + profile.Target.Node}}, nil, &pods); err != nil {
		return Prerequisites{}, err
	}
	for _, pod := range pods.Items {
		phase := stringField(nested(pod, "status"), "phase")
		if phase == "Succeeded" || phase == "Failed" {
			continue
		}
		requestedCPU, requestedMemory, err := podRequests(pod)
		if err != nil {
			return Prerequisites{}, err
		}
		cpu -= requestedCPU
		memory -= requestedMemory
	}
	if cpu < int64(profile.Guest.CPUs+1)*1000 || memory < int64(profile.Guest.MemoryMiB+2048)*(1<<20)*1000 {
		return Prerequisites{}, errors.New("selected development node lacks fresh request reservation headroom")
	}
	cilium, err := client.get(ctx, Object{APIVersion: "apps/v1", Kind: "DaemonSet", Resource: "daemonsets", Namespace: "kube-system", Name: "cilium"})
	if err != nil {
		return Prerequisites{}, err
	}
	status := nested(cilium, "status")
	desired, ok := status["desiredNumberScheduled"].(float64)
	ready, readyOK := status["numberReady"].(float64)
	if !ok || !readyOK || desired < 1 || ready != desired {
		return Prerequisites{}, errors.New("substrate Cilium daemon set is not fully ready")
	}
	return Prerequisites{ObservedAt: time.Now().UTC(), TargetClusterUID: profile.Target.KubeSystemUID, Node: profile.Target.Node,
		AvailableCPUMilli: cpu, AvailableMemoryMiB: memory / 1000 / (1 << 20), StorageClass: profile.Target.StorageClass,
		StorageReclaimPolicy: "Delete", StoragePlacementRequiresOperatorAcceptance: true, NetworkPolicyRequiresLiveDenialTest: true}, nil
}

func condition(object apiObject, name, value string) bool {
	conditions, _ := nested(object, "status")["conditions"].([]any)
	for _, item := range conditions {
		current, _ := item.(map[string]any)
		if stringField(current, "type") == name && stringField(current, "status") == value {
			return true
		}
	}
	return false
}

func networkSeparated(profile Profile, other string) bool {
	prefix, err := netip.ParsePrefix(other)
	if err != nil {
		return false
	}
	for _, value := range []string{profile.Network.GuestCIDR, profile.Network.PodCIDR, profile.Network.ServiceCIDR} {
		owned, _ := netip.ParsePrefix(value)
		if prefix.Overlaps(owned) {
			return false
		}
	}
	return true
}

// quantityMilli conservatively rounds positive Kubernetes quantities upward.
// It avoids floating-point resource accounting and rejects overflow.
func quantityMilli(value string) (int64, error) {
	if value == "" || len(value) > 64 {
		return 0, errors.New("development resource quantity is invalid")
	}
	scale := int64(1000)
	for _, suffix := range []struct {
		name   string
		factor int64
	}{{"Ei", 1 << 60}, {"Pi", 1 << 50}, {"Ti", 1 << 40}, {"Gi", 1 << 30}, {"Mi", 1 << 20}, {"Ki", 1 << 10}, {"E", 1_000_000_000_000_000_000}, {"P", 1_000_000_000_000_000}, {"T", 1_000_000_000_000}, {"G", 1_000_000_000}, {"M", 1_000_000}, {"k", 1000}, {"m", 0}} {
		if strings.HasSuffix(value, suffix.name) {
			value = strings.TrimSuffix(value, suffix.name)
			if suffix.name == "m" {
				scale = 1
			} else {
				if suffix.factor > (1<<63-1)/1000 {
					return 0, errors.New("development resource quantity overflows")
				}
				scale *= suffix.factor
			}
			break
		}
	}
	amount, ok := new(big.Rat).SetString(value)
	if !ok || amount.Sign() < 0 {
		return 0, errors.New("development resource quantity is invalid")
	}
	amount.Mul(amount, new(big.Rat).SetInt64(scale))
	whole, remainder := new(big.Int), new(big.Int)
	whole.QuoRem(amount.Num(), amount.Denom(), remainder)
	if remainder.Sign() > 0 {
		whole.Add(whole, big.NewInt(1))
	}
	if !whole.IsInt64() {
		return 0, errors.New("development resource quantity overflows")
	}
	return whole.Int64(), nil
}

func podRequests(pod apiObject) (int64, int64, error) {
	var cpu, memory int64
	spec := nested(pod, "spec")
	// Summing all init containers, including sidecars, over-reserves rather
	// than underestimating a parent's scheduler commitment.
	for _, group := range []string{"containers", "initContainers"} {
		containers, _ := spec[group].([]any)
		for _, item := range containers {
			container, _ := item.(map[string]any)
			requests := nested(container, "resources", "requests")
			for name, destination := range map[string]*int64{"cpu": &cpu, "memory": &memory} {
				if value := stringField(requests, name); value != "" {
					amount, err := quantityMilli(value)
					if err != nil || amount > (1<<63-1)-*destination {
						return 0, 0, fmt.Errorf("development pod %s reservation is invalid", name)
					}
					*destination += amount
				}
			}
		}
	}
	for name, destination := range map[string]*int64{"cpu": &cpu, "memory": &memory} {
		if value := stringField(nested(spec, "overhead"), name); value != "" {
			amount, err := quantityMilli(value)
			if err != nil || amount > (1<<63-1)-*destination {
				return 0, 0, errors.New("development pod overhead is invalid")
			}
			*destination += amount
		}
	}
	return cpu, memory, nil
}
