// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type apiObject map[string]any

type localObjectReference struct {
	Name string `json:"name"`
}

func renderObjects(state State) ([]apiObject, error) {
	profile := state.Profile
	plan, err := BuildPlan(profile)
	if err != nil || state.InstallationID != profile.InstallationID || state.ProfileSHA256 != plan.ProfileSHA256 || !hexDigest.MatchString(state.OwnerNonce) {
		return nil, ErrInvalidProfile
	}
	userData, err := cloudInit(state)
	if err != nil {
		return nil, err
	}
	cloudInitSource := map[string]any{}
	cloudInitSource["secretRef"] = localObjectReference{Name: "development-cloud-init"}
	objects := make([]apiObject, 0, len(plan.Objects))
	for _, ref := range plan.Objects {
		metadata := map[string]any{
			"name":        ref.Name,
			"labels":      map[string]any{OwnerLabel: state.InstallationID},
			"annotations": map[string]any{OwnerAnnotation: state.OwnerNonce, ProfileAnnotation: state.ProfileSHA256},
		}
		if ref.Namespace != "" {
			metadata["namespace"] = ref.Namespace
		}
		object := apiObject{"apiVersion": ref.APIVersion, "kind": ref.Kind, "metadata": metadata}
		switch ref.Kind {
		case "Namespace":
			metadata["labels"].(map[string]any)["pod-security.kubernetes.io/enforce"] = "privileged"
			metadata["labels"].(map[string]any)["pod-security.kubernetes.io/warn"] = "restricted"
		case "PriorityClass":
			object["value"] = -1000
			object["globalDefault"] = false
			object["preemptionPolicy"] = "Never"
			object["description"] = "Disposable CloudRING development guest; may not preempt existing workloads."
		case "ResourceQuota":
			object["spec"] = map[string]any{"hard": map[string]any{
				"requests.cpu": fmt.Sprint(profile.Guest.CPUs + 1), "limits.cpu": fmt.Sprint(profile.Guest.CPUs + 2),
				"requests.memory": fmt.Sprintf("%dGi", (profile.Guest.MemoryMiB+2048)/1024), "limits.memory": fmt.Sprintf("%dGi", (profile.Guest.MemoryMiB+4096)/1024),
				"requests.storage": fmt.Sprintf("%dGi", profile.Guest.DiskGiB), "persistentvolumeclaims": "1", "pods": "8",
				"services": "0", "services.nodeports": "0", "services.loadbalancers": "0", "secrets": "3", "configmaps": "4",
			}}
		case "CiliumNetworkPolicy":
			fqdn := make([]any, 0, len(profile.Network.EgressDomains))
			for _, domain := range profile.Network.EgressDomains {
				key := "matchName"
				if strings.HasPrefix(domain, "*.") {
					key = "matchPattern"
				}
				fqdn = append(fqdn, map[string]any{key: domain})
			}
			object["spec"] = map[string]any{
				"endpointSelector": map[string]any{}, "ingress": []any{},
				"egress": []any{
					map[string]any{"toEndpoints": []any{map[string]any{"matchLabels": map[string]any{
						"k8s:io.kubernetes.pod.namespace": "kube-system", "k8s:k8s-app": "kube-dns"}}},
						"toPorts": []any{map[string]any{"ports": []any{map[string]any{"port": "53", "protocol": "ANY"}},
							"rules": map[string]any{"dns": []any{map[string]any{"matchPattern": "*"}}}}}},
					map[string]any{"toFQDNs": fqdn, "toPorts": []any{map[string]any{"ports": []any{map[string]any{"port": "443", "protocol": "TCP"}}}}},
				},
				"egressDeny": []any{
					map[string]any{"toEntities": []string{"host", "remote-node", "kube-apiserver"}},
					map[string]any{"toCIDR": guestDeniedAddressClasses(),
						"toPorts": []any{map[string]any{"ports": []any{map[string]any{"port": "443", "protocol": "TCP"}}}}},
				},
			}
		case "Secret":
			object["type"] = "Opaque"
			object["immutable"] = true
			object["data"] = map[string]any{"userdata": base64.StdEncoding.EncodeToString([]byte(userData))}
		case "DataVolume":
			object["spec"] = map[string]any{
				"source": map[string]any{"registry": map[string]any{"url": "docker://" + profile.Artifacts.GuestImage, "pullMethod": "node"}},
				"storage": map[string]any{"accessModes": []string{"ReadWriteOnce"}, "volumeMode": "Filesystem", "storageClassName": profile.Target.StorageClass,
					"resources": map[string]any{"requests": map[string]any{"storage": fmt.Sprintf("%dGi", profile.Guest.DiskGiB)}}},
			}
		case "VirtualMachine":
			object["spec"] = map[string]any{"runStrategy": "Always", "template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{OwnerLabel: state.InstallationID},
					"annotations": map[string]any{OwnerAnnotation: state.OwnerNonce, ProfileAnnotation: state.ProfileSHA256}},
				"spec": map[string]any{"architecture": "amd64", "nodeSelector": map[string]any{"kubernetes.io/hostname": profile.Target.Node},
					"priorityClassName": profile.Target.PriorityClass, "terminationGracePeriodSeconds": 60,
					"domain": map[string]any{
						"cpu":      map[string]any{"sockets": 1, "cores": profile.Guest.CPUs, "threads": 1, "model": "host-passthrough"},
						"memory":   map[string]any{"guest": fmt.Sprintf("%dGi", profile.Guest.MemoryMiB/1024)},
						"firmware": map[string]any{"uuid": guestUUID(state.OwnerNonce)},
						"resources": map[string]any{"requests": map[string]any{"cpu": fmt.Sprint(profile.Guest.CPUs), "memory": fmt.Sprintf("%dGi", profile.Guest.MemoryMiB/1024)},
							"limits": map[string]any{"cpu": fmt.Sprint(profile.Guest.CPUs), "memory": fmt.Sprintf("%dGi", (profile.Guest.MemoryMiB+2048)/1024)}},
						"devices": map[string]any{
							"disks":      []any{map[string]any{"name": "root", "disk": map[string]any{"bus": "virtio"}}, map[string]any{"name": "cloudinit", "disk": map[string]any{"bus": "virtio"}}},
							"interfaces": []any{map[string]any{"name": "default", "masquerade": map[string]any{}, "ports": []any{map[string]any{"name": "ssh", "port": 22, "protocol": "TCP"}}}},
							"rng":        map[string]any{},
						},
					},
					"networks": []any{map[string]any{"name": "default", "pod": map[string]any{"vmNetworkCIDR": profile.Network.GuestCIDR}}},
					"volumes": []any{map[string]any{"name": "root", "dataVolume": map[string]any{"name": profile.Target.VirtualMachine + "-root"}},
						map[string]any{"name": "cloudinit", "cloudInitNoCloud": cloudInitSource}},
				},
			}}
		default:
			return nil, errors.New("unsupported development object")
		}
		objects = append(objects, object)
	}
	return objects, nil
}

func cloudInit(state State) (string, error) {
	identity, err := json.Marshal(map[string]string{"installationID": state.InstallationID, "ownerNonce": state.OwnerNonce,
		"profileSHA256": state.ProfileSHA256, "guestUUID": guestUUID(state.OwnerNonce)})
	if err != nil {
		return "", errors.New("encode guest ownership")
	}
	payload, err := yaml.Marshal(map[string]any{
		"hostname": state.InstallationID, "manage_etc_hosts": true, "ssh_pwauth": false, "disable_root": true, "ssh_deletekeys": true,
		"ssh_keys": map[string]string{"ed25519_private": state.Credentials.SSHHostPrivateKey, "ed25519_public": state.Credentials.SSHHostPublicKey},
		"users": []any{map[string]any{"name": "cloudring", "lock_passwd": true, "shell": "/bin/bash",
			"sudo": []string{"ALL=(ALL) NOPASSWD:ALL"}, "ssh_authorized_keys": []string{state.Credentials.SSHClientPublicKey}}},
		"write_files": []any{
			map[string]string{"path": "/var/lib/cloudring-development/identity.json", "owner": "root:root", "permissions": "0400", "content": string(identity)},
			map[string]string{"path": "/etc/ssh/sshd_config.d/99-cloudring-development.conf", "owner": "root:root", "permissions": "0600",
				"content": "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nAllowUsers cloudring\n"},
		},
		"runcmd": []any{[]string{"systemctl", "restart", "ssh"}},
	})
	if err != nil {
		return "", errors.New("encode owned guest initialization")
	}
	return "#cloud-config\n" + string(payload), nil
}

func guestUUID(nonce string) string {
	data, err := hex.DecodeString(nonce)
	if err != nil || len(data) != 32 {
		return ""
	}
	data[6] = data[6]&0x0f | 0x40
	data[8] = data[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", data[0:4], data[4:6], data[6:8], data[8:10], data[10:16])
}

func objectFingerprint(object apiObject) string {
	payload, _ := json.Marshal(object)
	defer clear(payload)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
