// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package openbaoauth

import (
	"regexp"
	"strings"
)

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)

// Validate enforces the fixed CloudRING v2 least-privilege profile.
func Validate(contract Contract) []Problem {
	problems := make([]Problem, 0)
	if contract.SchemaVersion != SchemaVersion {
		problems = append(problems, Problem{Path: "$.schemaVersion", Code: "unsupported_value"})
	}
	problems = append(problems, validateMount("$.authMount", contract.AuthMount)...)
	if contract.AuthMount == "kubernetes" {
		problems = append(problems, Problem{Path: "$.authMount", Code: "shared_mount_name_forbidden"})
	}
	if contract.AuthMountOwnership != DedicatedAuthMountOwnership {
		problems = append(problems, Problem{Path: "$.authMountOwnership", Code: "must_equal_dedicated_create_owned"})
	}
	problems = append(problems, validateMount("$.kvV2Mount", contract.KVV2Mount)...)
	problems = append(problems, validateDNSLabel("$.policyName", contract.PolicyName)...)
	if reservedPolicyName(contract.PolicyName) {
		problems = append(problems, Problem{Path: "$.policyName", Code: "reserved_policy_name"})
	}
	problems = append(problems, validateDNSLabel("$.roleName", contract.RoleName)...)
	problems = append(problems, validateDNSLabel("$.workloadIdentity.namespace", contract.WorkloadIdentity.Namespace)...)
	problems = append(problems, validateDNSLabel("$.workloadIdentity.serviceAccount", contract.WorkloadIdentity.ServiceAccount)...)
	if !validDataPrefix(contract.DataPrefix) {
		problems = append(problems, Problem{Path: "$.dataPrefix", Code: "invalid_safe_prefix"})
	}
	if contract.Audience != "openbao" {
		problems = append(problems, Problem{Path: "$.audience", Code: "must_equal_openbao"})
	}
	if contract.AliasNameSource != "serviceaccount_uid" {
		problems = append(problems, Problem{Path: "$.aliasNameSource", Code: "must_use_serviceaccount_uid"})
	}
	if contract.TokenTTL != "10m" {
		problems = append(problems, Problem{Path: "$.tokenTTL", Code: "must_equal_cloudring_10m_profile"})
	}
	if contract.TokenMaxTTL != "30m" {
		problems = append(problems, Problem{Path: "$.tokenMaxTTL", Code: "must_equal_cloudring_30m_profile"})
	}
	if !contract.TokenNoDefaultPolicy {
		problems = append(problems, Problem{Path: "$.tokenNoDefaultPolicy", Code: "must_be_true"})
	}
	return problems
}

func validateMount(path, value string) []Problem {
	problems := validateDNSLabel(path, value)
	if reservedMountName(value) {
		problems = append(problems, Problem{Path: path, Code: "reserved_name"})
	}
	return problems
}

func reservedMountName(value string) bool {
	switch value {
	case "auth", "default", "root", "sys", "token":
		return true
	default:
		return false
	}
}

func reservedPolicyName(value string) bool {
	switch value {
	case "default", "response-wrapping", "root":
		return true
	default:
		return false
	}
}

func validateDNSLabel(path, value string) []Problem {
	if !dnsLabel.MatchString(value) {
		return []Problem{{Path: path, Code: "invalid_dns_label"}}
	}
	return nil
}

func validDataPrefix(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") ||
		strings.ContainsAny(value, "*+\\\x00\r\n\t ") {
		return false
	}
	segments := strings.Split(value, "/")
	if len(segments) > 16 {
		return false
	}
	for _, segment := range segments {
		if segment == "." || segment == ".." || !dnsLabel.MatchString(segment) {
			return false
		}
	}
	return true
}
