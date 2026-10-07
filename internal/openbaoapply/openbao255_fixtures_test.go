// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package openbaoapply

import (
	"context"
	"encoding/json"
	"testing"
)

func TestExactValidatorsMatchOpenBao255ShapesAndRejectMutableDrift(t *testing.T) {
	request := validRequest(t)
	client := newFakeOpenBao(request)
	client.mount, client.config, client.policy, client.role, client.seed = true, true, true, true, true

	mount, _ := client.Read(context.Background(), "management-token", "sys/auth/"+request.Contract.AuthMount)
	if !exactMount(mount, client.plan.AuthMount) {
		t.Fatal("official 13-field auth mount rejected")
	}
	mountConfig, _ := object(mount.Data, "config")
	mountConfig["listing_visibility"] = "hidden"
	if exactMount(mount, client.plan.AuthMount) {
		t.Fatal("mutable auth tune drift accepted")
	}

	kvMount, _ := client.Read(context.Background(), "management-token", "sys/mounts/"+request.Contract.KVV2Mount)
	if !exactKVV2Mount(kvMount) {
		t.Fatal("official 13-field KV-v2 mount rejected")
	}
	kvMount.Data["plugin_version"] = "v9.9.9"
	if exactKVV2Mount(kvMount) {
		t.Fatal("external KV plugin accepted")
	}

	role, _ := client.Read(context.Background(), "management-token", "auth/"+request.Contract.AuthMount+"/role/"+request.Contract.RoleName)
	if !exactRole(role, client.plan.Role) || len(role.Data) != 15 {
		t.Fatalf("official 15-field role rejected: %#v", role.Data)
	}
	role.Data["policies"] = role.Data["token_policies"]
	if exactRole(role, client.plan.Role) {
		t.Fatal("deprecated role alias accepted as exact state")
	}

	policy, _ := client.Read(context.Background(), "management-token", "sys/policies/acl/"+request.Contract.PolicyName)
	if !exactPolicy(policy, request.Contract.PolicyName, client.plan.ACLPolicy) {
		t.Fatal("official five-field ACL policy rejected")
	}
	policy.Data["expiration"] = fakeSeedCreatedAt
	if exactPolicy(policy, request.Contract.PolicyName, client.plan.ACLPolicy) {
		t.Fatal("expiring ACL policy accepted")
	}

	metadata, _ := client.Read(context.Background(), "management-token", request.Contract.KVV2Mount+"/metadata/"+fullSeedPath(request))
	seed, _ := client.Read(context.Background(), "management-token", request.Contract.KVV2Mount+"/data/"+fullSeedPath(request))
	seedData, _ := decodedSeed(request.Seed)
	createdAt, exact := exactSeed(metadata, seed, seedData)
	if !exact || createdAt != fakeSeedCreatedAt {
		t.Fatal("official KV-v2 metadata/data shape rejected")
	}
	metadata.Data["current_metadata_version"] = jsonNumber("1")
	if _, exact := exactSeed(metadata, seed, seedData); exact {
		t.Fatal("KV custom-metadata history drift accepted")
	}
}

func TestExactSeedAcceptsCurrentValueAfterCredentialRotation(t *testing.T) {
	request := validRequest(t)
	client := newFakeOpenBao(request)
	client.mount, client.config, client.policy, client.role, client.seed = true, true, true, true, true
	metadata, _ := client.Read(context.Background(), "management-token", request.Contract.KVV2Mount+"/metadata/"+fullSeedPath(request))
	seed, _ := client.Read(context.Background(), "management-token", request.Contract.KVV2Mount+"/data/"+fullSeedPath(request))
	seedData, _ := decodedSeed(request.Seed)

	const secondVersionAt = "2026-07-14T12:00:00.123456789Z"
	const currentVersionAt = "2026-07-15T12:00:00.123456789Z"
	metadata.Data["versions"] = map[string]any{
		"1": map[string]any{"created_time": fakeSeedCreatedAt, "deletion_time": "", "destroyed": false},
		"2": map[string]any{"created_time": secondVersionAt, "deletion_time": "", "destroyed": false},
		"3": map[string]any{"created_time": currentVersionAt, "deletion_time": "", "destroyed": false},
	}
	metadata.Data["current_version"] = jsonNumber("3")
	metadata.Data["updated_time"] = currentVersionAt
	seed.Data["metadata"].(map[string]any)["version"] = jsonNumber("3")
	seed.Data["metadata"].(map[string]any)["created_time"] = currentVersionAt

	createdAt, exact := exactSeed(metadata, seed, seedData)
	if !exact || createdAt != currentVersionAt {
		t.Fatalf("current exact value after rotation rejected: exact=%v createdAt=%q", exact, createdAt)
	}
	if !exactSeedData(seed, seedData) {
		t.Fatal("current workload value after rotation rejected")
	}

	delete(metadata.Data["versions"].(map[string]any), "3")
	if _, exact := exactSeed(metadata, seed, seedData); exact {
		t.Fatal("metadata without the declared current version accepted")
	}
	metadata.Data["versions"].(map[string]any)["3"] = map[string]any{
		"created_time": currentVersionAt, "deletion_time": "", "destroyed": true,
	}
	if _, exact := exactSeed(metadata, seed, seedData); exact {
		t.Fatal("destroyed current version accepted")
	}
}

func jsonNumber(value string) interface{} {
	return json.Number(value)
}
