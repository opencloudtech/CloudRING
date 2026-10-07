// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package openbaoapply

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestLeaseFromPayloadRequiresTypedIdentityAndMicroTime(t *testing.T) {
	valid := decodeLeaseFixture(t, `{"apiVersion":"coordination.k8s.io/v1","kind":"Lease","metadata":{"name":"bootstrap","namespace":"system","uid":"lease-uid","resourceVersion":"1"},"spec":{"holderIdentity":"holder","leaseDurationSeconds":30,"acquireTime":"2026-07-13T12:00:00.123456Z","renewTime":"2026-07-13T12:00:01.123456Z"}}`)
	lease, err := leaseFromPayload(valid)
	if err != nil || lease.Name != "bootstrap" || lease.Namespace != "system" || lease.AcquireTime.Nanosecond()%int(time.Microsecond) != 0 {
		t.Fatalf("lease=%+v err=%v", lease, err)
	}
	for _, fixture := range []string{
		`{"metadata":{"name":"bootstrap","namespace":"system","uid":"lease-uid","resourceVersion":"1"},"spec":{"holderIdentity":{}}}`,
		`{"metadata":{"name":"bootstrap","namespace":"system","uid":"lease-uid","resourceVersion":"1"},"spec":{"leaseDurationSeconds":"30"}}`,
		`{"metadata":{"name":"bootstrap","namespace":"system","uid":"lease-uid","resourceVersion":"1"},"spec":{"acquireTime":"2026-07-13T12:00:00.123456789Z"}}`,
	} {
		if _, err := leaseFromPayload(decodeLeaseFixture(t, fixture)); err == nil {
			t.Fatalf("malformed Lease accepted: %s", fixture)
		}
	}
}

func TestExactLeaseUpdateRequiresAdvancedVersionAndExactEcho(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	requested := Lease{Name: "bootstrap", Namespace: "system", UID: "uid", ResourceVersion: "1", HolderIdentity: "holder", LeaseDurationSec: 30, AcquireTime: now, RenewTime: now}
	updated := requested
	updated.ResourceVersion = "2"
	if !exactLeaseUpdate(requested, updated) {
		t.Fatal("exact advanced Lease update rejected")
	}
	mutations := []func(*Lease){
		func(value *Lease) { value.ResourceVersion = "1" },
		func(value *Lease) { value.UID = "other" },
		func(value *Lease) { value.HolderIdentity = "other" },
		func(value *Lease) { value.LeaseDurationSec = 31 },
		func(value *Lease) { value.RenewTime = value.RenewTime.Add(time.Microsecond) },
	}
	for index, mutate := range mutations {
		candidate := updated
		mutate(&candidate)
		if exactLeaseUpdate(requested, candidate) {
			t.Fatalf("drift %d accepted: %+v", index, candidate)
		}
	}
}

func decodeLeaseFixture(t *testing.T, fixture string) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewBufferString(fixture))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
