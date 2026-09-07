// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"fmt"
	"net/netip"
	"net/url"
)

// Object identifies the exact API object which an operation may create.
// UID is filled only from successful API readback, never manufactured locally.
type Object struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Resource   string `json:"resource"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
}

type Plan struct {
	APIVersion            string   `json:"apiVersion"`
	InstallationID        string   `json:"installationID"`
	ProfileSHA256         string   `json:"profileSHA256"`
	Profile               string   `json:"profile"`
	ProductionReady       bool     `json:"productionReady"`
	TargetClusterUID      string   `json:"targetClusterUID"`
	Objects               []Object `json:"objects"`
	GuestAddress          string   `json:"guestAddress"`
	GuestCommands         []string `json:"guestCommands"`
	PublicOrigin          string   `json:"publicOrigin"`
	RequiredPrerequisites []string `json:"requiredPrerequisites"`
}

func BuildPlan(profile Profile) (Plan, error) {
	if err := Validate(profile, Development); err != nil {
		return Plan{}, err
	}
	namespace := profile.Target.Namespace
	objects := []Object{{APIVersion: "v1", Kind: "Namespace", Resource: "namespaces", Name: namespace}}
	if profile.Target.PriorityClass == namespace {
		objects = append(objects, Object{APIVersion: "scheduling.k8s.io/v1", Kind: "PriorityClass", Resource: "priorityclasses", Name: namespace})
	}
	objects = append(objects,
		Object{APIVersion: "v1", Kind: "ResourceQuota", Resource: "resourcequotas", Namespace: namespace, Name: "development-budget"},
		Object{APIVersion: "cilium.io/v2", Kind: "CiliumNetworkPolicy", Resource: "ciliumnetworkpolicies", Namespace: namespace, Name: "development-isolation"},
		Object{APIVersion: "v1", Kind: "Secret", Resource: "secrets", Namespace: namespace, Name: "development-cloud-init"},
		Object{APIVersion: "cdi.kubevirt.io/v1beta1", Kind: "DataVolume", Resource: "datavolumes", Namespace: namespace, Name: profile.Target.VirtualMachine + "-root"},
		Object{APIVersion: "kubevirt.io/v1", Kind: "VirtualMachine", Resource: "virtualmachines", Namespace: namespace, Name: profile.Target.VirtualMachine},
	)
	return Plan{
		APIVersion: "cloudring.development-plan/v1", InstallationID: profile.InstallationID,
		ProfileSHA256: Fingerprint(profile), Profile: Development, TargetClusterUID: profile.Target.KubeSystemUID,
		Objects: objects, GuestAddress: guestAddress(profile).String(), PublicOrigin: profile.Network.PublicOrigin,
		GuestCommands: []string{
			"verify new guest identity and installation ownership",
			"install SHA-256 verified upstream containerd, runc, CNI and Kubernetes artifacts",
			"bootstrap one upstream kubeadm control plane with pinned images",
			"install pinned Cilium and wait for the real node network",
			"initialize isolated PostgreSQL roles, TLS and durable storage",
			"run public schema migration with the owner role",
			"serve the public API and portal with only the application role",
		},
		RequiredPrerequisites: []string{
			"exact selected kube-system UID and API server",
			"supported KubeVirt, CDI, Cilium policy enforcement and Longhorn Delete-reclaim storage class",
			fmt.Sprintf("fresh node reservation headroom: at least %d CPU and %d MiB", profile.Guest.CPUs+1, profile.Guest.MemoryMiB+2048),
			"fresh storage placement and failure-headroom acceptance",
			"nonoverlapping parent, guest, pod and service networks",
			"read/create/delete permissions for the listed new objects and VM port-forward",
			"all listed namespace/object names absent or owned by this exact recorded installation",
			"public pinned downloads and their restricted registry/CDN egress",
		},
	}, nil
}

func guestAddress(profile Profile) netip.Addr {
	prefix, _ := netip.ParsePrefix(profile.Network.GuestCIDR)
	return prefix.Addr().Next().Next()
}

func apiHostname(profile Profile) string {
	origin, _ := url.Parse(profile.Network.PublicOrigin)
	return origin.Hostname()
}
