// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package oneserverloss

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const maximumAggregateListBytes = 32 << 20

var (
	nodeResource = Resource{Version: "v1", Resource: "nodes", ListKind: "NodeList", Kind: "Node"}
	podResource  = Resource{Version: "v1", Resource: "pods", ListKind: "PodList", Kind: "Pod"}
	vmResource   = Resource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachines", ListKind: "VirtualMachineList", Kind: "VirtualMachine"}
	vmiResource  = Resource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstances", ListKind: "VirtualMachineInstanceList", Kind: "VirtualMachineInstance"}
)

type objectMetadata struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	ResourceVersion   string            `json:"resourceVersion"`
	Labels            map[string]string `json:"labels"`
	DeletionTimestamp *string           `json:"deletionTimestamp"`
}

type condition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

type nodeObject struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   objectMetadata `json:"metadata"`
	Status     struct {
		Conditions []condition `json:"conditions"`
	} `json:"status"`
}

type podObject struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   objectMetadata `json:"metadata"`
	Spec       struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		Phase      string      `json:"phase"`
		Conditions []condition `json:"conditions"`
	} `json:"status"`
}

type vmObject struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   objectMetadata `json:"metadata"`
	Status     struct {
		Ready bool `json:"ready"`
	} `json:"status"`
}

type vmiObject struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   objectMetadata `json:"metadata"`
	Status     struct {
		Phase      string      `json:"phase"`
		NodeName   string      `json:"nodeName"`
		Conditions []condition `json:"conditions"`
	} `json:"status"`
}

type listEnvelope struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		ResourceVersion string `json:"resourceVersion"`
		Continue        string `json:"continue"`
	} `json:"metadata"`
	Items []json.RawMessage `json:"items"`
}

type objectEnvelope struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   objectMetadata `json:"metadata"`
}

func listAll(ctx context.Context, reader Reader, resource Resource, namespace, selector string) ([][]byte, error) {
	continuation := ""
	resourceVersion := ""
	seenContinuations := make(map[string]struct{})
	items := make([][]byte, 0)
	identities := make(map[string]struct{})
	totalBytes := 0
	for pageNumber := 0; pageNumber < 20; pageNumber++ {
		payload, err := reader.ListPage(ctx, resource, namespace, selector, continuation, 500)
		if err != nil {
			return nil, errors.New("read Kubernetes list page")
		}
		totalBytes += len(payload)
		if totalBytes > maximumAggregateListBytes {
			zeroBytes(payload)
			return nil, errors.New("Kubernetes list exceeds byte bound")
		}
		var page listEnvelope
		if strictjson.Decode(payload, &page) != nil || page.APIVersion != apiVersion(resource) || page.Kind != resource.ListKind || page.Metadata.ResourceVersion == "" {
			zeroBytes(payload)
			return nil, errors.New("decode Kubernetes list page")
		}
		if resourceVersion == "" {
			resourceVersion = page.Metadata.ResourceVersion
		} else if resourceVersion != page.Metadata.ResourceVersion {
			zeroBytes(payload)
			return nil, errors.New("Kubernetes list snapshot changed across pages")
		}
		for _, raw := range page.Items {
			var envelope objectEnvelope
			if strictjson.Decode(raw, &envelope) != nil || envelope.APIVersion != apiVersion(resource) || envelope.Kind != resource.Kind ||
				!validObjectMetadata(envelope.Metadata, namespace) {
				zeroBytes(payload)
				return nil, errors.New("decode Kubernetes list item")
			}
			identity := envelope.Metadata.Namespace + "\x00" + envelope.Metadata.Name + "\x00" + envelope.Metadata.UID
			if _, duplicate := identities[identity]; duplicate {
				zeroBytes(payload)
				return nil, errors.New("Kubernetes list contains duplicate identity")
			}
			identities[identity] = struct{}{}
			items = append(items, append([]byte(nil), raw...))
			if len(items) > 10000 {
				zeroBytes(payload)
				return nil, errors.New("Kubernetes list exceeds object bound")
			}
		}
		if page.Metadata.Continue == "" {
			zeroBytes(payload)
			sort.Slice(items, func(left, right int) bool {
				return objectSortIdentity(items[left]) < objectSortIdentity(items[right])
			})
			return items, nil
		}
		if len(page.Metadata.Continue) > 8192 {
			zeroBytes(payload)
			return nil, errors.New("Kubernetes continuation token is invalid")
		}
		if _, duplicate := seenContinuations[page.Metadata.Continue]; duplicate {
			zeroBytes(payload)
			return nil, errors.New("Kubernetes continuation cycle")
		}
		seenContinuations[page.Metadata.Continue] = struct{}{}
		continuation = page.Metadata.Continue
		zeroBytes(payload)
	}
	return nil, errors.New("Kubernetes list exceeds page bound")
}

func objectSortIdentity(raw []byte) string {
	var envelope objectEnvelope
	if strictjson.Decode(raw, &envelope) != nil {
		return ""
	}
	return envelope.Metadata.Namespace + "\x00" + envelope.Metadata.Name + "\x00" + envelope.Metadata.UID
}

func decodeNode(raw []byte) (nodeObject, error) {
	var node nodeObject
	if strictjson.Decode(raw, &node) != nil || node.APIVersion != "v1" || node.Kind != "Node" || !validObjectMetadata(node.Metadata, "") {
		return nodeObject{}, errors.New("decode Kubernetes Node")
	}
	return node, nil
}

func decodePod(raw []byte, namespace string) (podObject, error) {
	var pod podObject
	if strictjson.Decode(raw, &pod) != nil || pod.APIVersion != "v1" || pod.Kind != "Pod" || !validObjectMetadata(pod.Metadata, namespace) {
		return podObject{}, errors.New("decode Kubernetes Pod")
	}
	return pod, nil
}

func decodeVM(raw []byte, namespace, name string) (vmObject, error) {
	var vm vmObject
	if strictjson.Decode(raw, &vm) != nil || vm.APIVersion != "kubevirt.io/v1" || vm.Kind != "VirtualMachine" ||
		!validObjectMetadata(vm.Metadata, namespace) || vm.Metadata.Name != name {
		return vmObject{}, errors.New("decode KubeVirt VirtualMachine")
	}
	return vm, nil
}

func decodeVMI(raw []byte, namespace, name string) (vmiObject, error) {
	var vmi vmiObject
	if strictjson.Decode(raw, &vmi) != nil || vmi.APIVersion != "kubevirt.io/v1" || vmi.Kind != "VirtualMachineInstance" ||
		!validObjectMetadata(vmi.Metadata, namespace) || vmi.Metadata.Name != name {
		return vmiObject{}, errors.New("decode KubeVirt VirtualMachineInstance")
	}
	return vmi, nil
}

func validObjectMetadata(metadata objectMetadata, namespace string) bool {
	if !validDNSName(metadata.Name) || metadata.UID == "" || len(metadata.UID) > 256 || metadata.ResourceVersion == "" || len(metadata.ResourceVersion) > 256 ||
		metadata.DeletionTimestamp != nil && canonicalTimestamp(*metadata.DeletionTimestamp) == nil {
		return false
	}
	return namespace == "" || metadata.Namespace == namespace
}

func objectTerminating(metadata objectMetadata) bool {
	return metadata.DeletionTimestamp != nil
}

func conditionTrue(conditions []condition, expected string) bool {
	found := false
	for _, candidate := range conditions {
		if candidate.Type != expected {
			continue
		}
		if found || candidate.Status != "True" {
			return false
		}
		found = true
	}
	return found
}

func apiVersion(resource Resource) string {
	if resource.Group == "" {
		return resource.Version
	}
	return resource.Group + "/" + resource.Version
}

func zeroPayloads(payloads [][]byte) {
	for _, payload := range payloads {
		zeroBytes(payload)
	}
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
