// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package oneserverloss

import (
	"testing"
	"time"
)

func TestValidateReadyMarkerFreshnessRejectsStaleMarkerWithoutChangingOfflineValidation(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	marker := readyMarkerAt(now.Add(-2 * time.Minute))
	if err := ValidateReadyMarker(marker); err != nil {
		t.Fatalf("offline ValidateReadyMarker rejected structurally valid historical marker: %v", err)
	}
	if err := ValidateReadyMarkerFreshness(marker, now, time.Minute, 5*time.Second); err == nil {
		t.Fatal("ValidateReadyMarkerFreshness accepted a stale marker")
	}
}

func TestValidateReadyMarkerFreshnessRejectsFutureMarker(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	marker := readyMarkerAt(now.Add(6 * time.Second))
	if err := ValidateReadyMarkerFreshness(marker, now, time.Minute, 5*time.Second); err == nil {
		t.Fatal("ValidateReadyMarkerFreshness accepted a marker beyond future skew")
	}
}

func TestValidateReadyMarkerFreshnessAcceptsConfiguredBoundaries(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	for _, readyAt := range []time.Time{now.Add(-time.Minute), now.Add(5 * time.Second)} {
		if err := ValidateReadyMarkerFreshness(readyMarkerAt(readyAt), now, time.Minute, 5*time.Second); err != nil {
			t.Fatalf("ValidateReadyMarkerFreshness rejected configured boundary %s: %v", readyAt, err)
		}
	}
}

func TestValidateReadyMarkerFreshnessRejectsInvalidPolicy(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	marker := readyMarkerAt(now)
	for _, policy := range []struct {
		now        time.Time
		maximumAge time.Duration
		futureSkew time.Duration
	}{
		{maximumAge: time.Minute, futureSkew: time.Second},
		{now: now, maximumAge: 0, futureSkew: time.Second},
		{now: now, maximumAge: time.Minute, futureSkew: -time.Second},
	} {
		if err := ValidateReadyMarkerFreshness(marker, policy.now, policy.maximumAge, policy.futureSkew); err == nil {
			t.Fatal("ValidateReadyMarkerFreshness accepted an invalid temporal policy")
		}
	}
}

func readyMarkerAt(readyAt time.Time) ReadyMarker {
	marker := ReadyMarker{
		SchemaVersion:             ReadyMarkerSchemaVersion,
		Status:                    ReadyMarkerStatus,
		RequestSHA256:             testDigest("request"),
		RunNonceSHA256:            testDigest("nonce"),
		TargetNodeUIDSHA256:       testDigest("node"),
		KubectlExecutableSHA256:   testDigest("kubectl"),
		ProbeAdapterSHA256:        testDigest("probe"),
		BaselineControlPlaneNodes: 3,
		BaselineEtcdMembers:       3,
		BaselineAPIServerMembers:  3,
		ReadyAt:                   readyAt.UTC().Format(time.RFC3339Nano),
	}
	marker.MarkerSHA256 = markerDigest(marker)
	return marker
}
