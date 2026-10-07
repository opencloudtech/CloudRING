// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package etcdrecovery

import (
	"strings"
	"testing"
)

func TestInputSecretProjectionBindingIsCanonicalAndNonSelfReferential(t *testing.T) {
	projection := InputSecretProjection{
		SchemaVersion:       InputProjectionSchemaVersion,
		Namespace:           "kube-system",
		ProjectedObjectName: "cloudring-etcd-recovery-request",
		SecretKey:           "request.json",
		MountPath:           DefaultRequestPath,
		DefaultMode:         0o440,
		Optional:            false,
		ReadOnly:            true,
	}
	payload, err := CanonicalInputSecretProjection(projection)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := InputSecretProjectionSHA256(projection)
	if err != nil {
		t.Fatal(err)
	}
	if digest != digestBytes(payload) || strings.Contains(string(payload), "inputSecretSha256") {
		t.Fatalf("projection payload=%s digest=%s", payload, digest)
	}
}

func TestInputSecretProjectionRejectsUnsafeOrAmbiguousConfiguration(t *testing.T) {
	valid := InputSecretProjection{
		SchemaVersion:       InputProjectionSchemaVersion,
		Namespace:           "kube-system",
		ProjectedObjectName: "cloudring-etcd-recovery-request",
		SecretKey:           "request.json",
		MountPath:           DefaultRequestPath,
		DefaultMode:         0o440,
		ReadOnly:            true,
	}
	for _, mutate := range []func(*InputSecretProjection){
		func(value *InputSecretProjection) { value.SchemaVersion = "other" },
		func(value *InputSecretProjection) { value.Namespace = "unsafe.namespace" },
		func(value *InputSecretProjection) { value.ProjectedObjectName = "../secret" },
		func(value *InputSecretProjection) { value.SecretKey = "other.json" },
		func(value *InputSecretProjection) { value.MountPath = "/tmp/request.json" },
		func(value *InputSecretProjection) { value.DefaultMode = 0o644 },
		func(value *InputSecretProjection) { value.Optional = true },
		func(value *InputSecretProjection) { value.ReadOnly = false },
	} {
		candidate := valid
		mutate(&candidate)
		if _, err := InputSecretProjectionSHA256(candidate); err == nil {
			t.Fatalf("accepted unsafe projection: %#v", candidate)
		}
	}
}
