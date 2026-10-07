// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package openbaobootstrap

import (
	"slices"
	"strings"
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/openbaoauth"
)

func TestBuildManagementDelegationIsExactAndSelfAuditable(t *testing.T) {
	contract := openbaoauth.Contract{
		SchemaVersion: openbaoauth.SchemaVersion, AuthMount: "kubernetes-velero", AuthMountOwnership: openbaoauth.DedicatedAuthMountOwnership,
		KVV2Mount: "cloudring", DataPrefix: "services/velero", PolicyName: "velero-kv-read", RoleName: "velero",
		WorkloadIdentity: openbaoauth.WorkloadIdentity{Namespace: "velero", ServiceAccount: "velero"}, Audience: "openbao",
		AliasNameSource: "serviceaccount_uid", TokenTTL: "10m", TokenMaxTTL: "30m", TokenNoDefaultPolicy: true,
	}
	delegation, err := BuildManagementDelegation(contract, "velero-bootstrap", "cloud-credentials")
	if err != nil {
		t.Fatal(err)
	}
	if len(delegation.Paths) != 12 || !equal(delegation.Paths["sys/policies/acl/velero-bootstrap"], []string{"read"}) || !equal(delegation.Paths["auth/token/revoke-self"], []string{"update"}) || !equal(delegation.Paths["cloudring/metadata/services/velero/cloud-credentials"], []string{"read"}) || !equal(delegation.Paths["sys/mounts/cloudring"], []string{"read", "update", "sudo"}) {
		t.Fatalf("unexpected paths: %#v", delegation.Paths)
	}
	if strings.Count(delegation.Body, "path \"") != len(delegation.Paths) || strings.Contains(delegation.Body, "*") {
		t.Fatalf("policy is not exact: %q", delegation.Body)
	}
	authMountCapabilities := delegation.Paths["sys/auth/kubernetes-velero"]
	if len(authMountCapabilities) == 0 {
		t.Fatal("auth-mount delegation is missing")
	}
	for index := range authMountCapabilities {
		authMountCapabilities[index] = "root"
		break
	}
	again, _ := BuildManagementDelegation(contract, "velero-bootstrap", "cloud-credentials")
	if again.Paths["sys/auth/kubernetes-velero"][0] != "read" {
		t.Fatal("returned paths share mutable state")
	}
}

func TestBuildManagementDelegationRejectsUnsafeTarget(t *testing.T) {
	if _, err := BuildManagementDelegation(openbaoauth.Contract{}, "root", "../secret"); err == nil {
		t.Fatal("unsafe delegation target accepted")
	}
}

func equal(left, right []string) bool {
	return slices.Equal(left, right)
}
