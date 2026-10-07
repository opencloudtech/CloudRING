// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Package openbaobootstrap exposes the non-secret, deterministic delegation
// contract shared by the protected credential broker and the apply executor.
package openbaobootstrap

import (
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/opencloudtech/CloudRING/pkg/openbaoauth"
)

var safeComponent = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)

// ManagementDelegation is the exact non-secret ACL delegated to one apply
// execution. Body is canonical HCL; Paths is a defensive copy of its grants.
type ManagementDelegation struct {
	Body  string
	Paths map[string][]string
}

// BuildManagementDelegation derives the sole acceptable management policy for
// one dedicated Kubernetes-auth mount and one create-only KV-v2 seed.
func BuildManagementDelegation(contract openbaoauth.Contract, managementPolicyName, seedRelativePath string) (ManagementDelegation, error) {
	if problems := openbaoauth.Validate(contract); len(problems) != 0 || !safeComponent.MatchString(managementPolicyName) || managementPolicyName == "root" || managementPolicyName == "default" || managementPolicyName == "response-wrapping" || managementPolicyName == contract.PolicyName || !safeRelativePath(seedRelativePath) {
		return ManagementDelegation{}, errors.New("invalid OpenBao management delegation target")
	}
	seed := contract.DataPrefix + "/" + seedRelativePath
	paths := map[string][]string{
		"auth/token/lookup-self":                                    {"read"},
		"auth/token/revoke-self":                                    {"update"},
		"sys/capabilities-self":                                     {"update"},
		"sys/auth/" + contract.AuthMount:                            {"read", "update", "delete", "sudo"},
		"auth/" + contract.AuthMount + "/config":                    {"read", "update"},
		"auth/" + contract.AuthMount + "/role":                      {"list"},
		"auth/" + contract.AuthMount + "/role/" + contract.RoleName: {"create", "read", "delete"},
		"sys/mounts/" + contract.KVV2Mount:                          {"read", "update", "sudo"},
		"sys/policies/acl/" + contract.PolicyName:                   {"read", "update", "delete"},
		"sys/policies/acl/" + managementPolicyName:                  {"read"},
		contract.KVV2Mount + "/metadata/" + seed:                    {"read"},
		contract.KVV2Mount + "/data/" + seed:                        {"create", "read"},
	}
	keys := make([]string, 0, len(paths))
	for path := range paths {
		keys = append(keys, path)
	}
	sort.Strings(keys)
	var body strings.Builder
	for _, path := range keys {
		body.WriteString("path \"")
		body.WriteString(path)
		body.WriteString("\" {\n  capabilities = [")
		for index, capability := range paths[path] {
			if index != 0 {
				body.WriteString(", ")
			}
			body.WriteString("\"")
			body.WriteString(capability)
			body.WriteString("\"")
		}
		body.WriteString("]\n}\n")
	}
	return ManagementDelegation{Body: body.String(), Paths: clonePaths(paths)}, nil
}

func safeRelativePath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) > 8 {
		return false
	}
	for _, part := range parts {
		if !safeComponent.MatchString(part) {
			return false
		}
	}
	return true
}

func clonePaths(source map[string][]string) map[string][]string {
	result := make(map[string][]string, len(source))
	for path, capabilities := range source {
		result[path] = append([]string(nil), capabilities...)
	}
	return result
}
