// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package sliceoracles_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/rsi"
	"github.com/opencloudtech/CloudRING/pkg/sliceoracles"
)

func loadCanonicalBatch(t *testing.T) *sliceoracles.Batch {
	t.Helper()
	path := filepath.Join("..", "..", "contracts", "slice-oracles", "oracles-32.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	batch, err := sliceoracles.ParseBatch(data)
	if err != nil {
		t.Fatalf("ParseBatch: %v", err)
	}
	return batch
}

func loadCompliantRSIProfile(t *testing.T) rsi.CandidateProfile {
	t.Helper()
	path := filepath.Join("..", "..", "contracts", "rsi-governance", "fixtures", "compliant-k3-profile.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	prof, err := rsi.ParseProfile(data)
	if err != nil {
		t.Fatalf("ParseProfile: %v", err)
	}
	return prof
}

func validLKGState() sliceoracles.LKGSafetyState {
	return sliceoracles.LKGSafetyState{
		ImmutableBootloaderVerified:  true,
		PinnedLKGSlots:               2,
		SoakMinutes:                  30,
		WebhookBypassVerified:        true,
		PreMigrationSnapshotVerified: true,
		MetaRSISelfCheckPassed:       true,
		CandidateSHA:                 "a326123af6ca994ce876bb786dff7683f181ca36",
		QuarantinedSHAs:              []string{"deadbeef00000000000000000000000000000000"},
	}
}

func TestCanonical32OracleBatchAndNoNewHWPartition(t *testing.T) {
	batch := loadCanonicalBatch(t)
	noHW, deferredHW := batch.PartitionNoNewHardware()
	if len(noHW) != 28 {
		t.Fatalf("expected 28 no-new-hardware slices, got %d", len(noHW))
	}
	if len(deferredHW) != 4 {
		t.Fatalf("expected 4 deferred Fork 3 hardware slices, got %d", len(deferredHW))
	}

	// Initially with C01 accepted, SP01 and C06 are immediately ready in the 2-agent parallel queue.
	completedCORE := map[string]bool{"C01": true}
	completedFULL := map[string]bool{"C01": true}
	ready := batch.ReadyNoNewHardwareQueue(completedCORE, completedFULL)
	if len(ready) != 2 || ready[0] != "SP01:FULL" || ready[1] != "C06:FULL" {
		t.Fatalf("expected initial ready pair [SP01:FULL C06:FULL], got %v", ready)
	}

	// Verify Fork 2A split unlocking: once C01..C11 are accepted (before C13 billing and C14 experience!),
	// C15, C16, and DNSAAS CORE builds unlock immediately in parallel with C12.
	for _, s := range []string{"SP01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "C09", "C10", "C11"} {
		completedCORE[s] = true
		completedFULL[s] = true
	}
	readyAfterC11 := batch.ReadyNoNewHardwareQueue(completedCORE, completedFULL)
	wantAfterC11 := []string{"C12:FULL", "C15:CORE", "C16:CORE", "DNSAAS:CORE"}
	if len(readyAfterC11) != len(wantAfterC11) {
		t.Fatalf("after C11 expected %v, got %v", wantAfterC11, readyAfterC11)
	}
	for i := range wantAfterC11 {
		if readyAfterC11[i] != wantAfterC11[i] {
			t.Fatalf("after C11[%d]: expected %s, got %s", i, wantAfterC11[i], readyAfterC11[i])
		}
	}
}

func TestFork2AConcurrentWritePRValidation(t *testing.T) {
	batch := loadCanonicalBatch(t)

	// Valid pair: SP01 and C06 have disjoint paths.
	err := batch.ValidateConcurrentWritePRs([]sliceoracles.ActivePR{
		{SliceID: "SP01", TouchedPaths: []string{"pkg/rsi", "pkg/sliceoracles"}},
		{SliceID: "C06", TouchedPaths: []string{"pkg/backup", "pkg/dataact"}},
	})
	if err != nil {
		t.Fatalf("expected disjoint 2-PR pair to pass, got: %v", err)
	}

	// Reject overlapping paths.
	err = batch.ValidateConcurrentWritePRs([]sliceoracles.ActivePR{
		{SliceID: "C02", TouchedPaths: []string{"internal/portal/ui"}},
		{SliceID: "C14", TouchedPaths: []string{"internal/portal"}},
	})
	if err == nil {
		t.Fatal("expected overlapping paths across concurrent PRs to fail")
	}

	// Reject >2 active write PRs.
	err = batch.ValidateConcurrentWritePRs([]sliceoracles.ActivePR{
		{SliceID: "SP01", TouchedPaths: []string{"pkg/rsi"}},
		{SliceID: "C06", TouchedPaths: []string{"pkg/backup"}},
		{SliceID: "C03", TouchedPaths: []string{"pkg/transactionalstate"}},
	})
	if err == nil {
		t.Fatal("expected 3 concurrent write PRs to fail Fork 2A cap of 2")
	}

	// Reject inputs that only differ by spelling: dot segments, blank or escaping paths, padded or unknown slice ids.
	rejected := []struct {
		name   string
		active []sliceoracles.ActivePR
	}{
		{"dot-segment overlap", []sliceoracles.ActivePR{
			{SliceID: "SP01", TouchedPaths: []string{"./pkg/rsi"}},
			{SliceID: "C06", TouchedPaths: []string{"pkg/rsi/"}},
		}},
		{"blank path", []sliceoracles.ActivePR{
			{SliceID: "SP01", TouchedPaths: []string{" "}},
			{SliceID: "C06", TouchedPaths: []string{"pkg/backup"}},
		}},
		{"escaping path", []sliceoracles.ActivePR{
			{SliceID: "SP01", TouchedPaths: []string{"pkg/../../etc"}},
			{SliceID: "C06", TouchedPaths: []string{"pkg/backup"}},
		}},
		{"absolute path", []sliceoracles.ActivePR{
			{SliceID: "SP01", TouchedPaths: []string{"/pkg/rsi"}},
			{SliceID: "C06", TouchedPaths: []string{"pkg/backup"}},
		}},
		{"padded duplicate slice", []sliceoracles.ActivePR{
			{SliceID: "SP01 ", TouchedPaths: []string{"pkg/rsi"}},
			{SliceID: "SP01", TouchedPaths: []string{"pkg/sliceoracles"}},
		}},
		{"unknown slice", []sliceoracles.ActivePR{
			{SliceID: "C99", TouchedPaths: []string{"pkg/rsi"}},
			{SliceID: "C06", TouchedPaths: []string{"pkg/backup"}},
		}},
	}
	for _, tc := range rejected {
		if err := batch.ValidateConcurrentWritePRs(tc.active); err == nil {
			t.Errorf("%s: expected rejection, got nil", tc.name)
		}
	}
}

func TestAutonomousSliceEvaluationAndDeferredFork3Guard(t *testing.T) {
	batch := loadCanonicalBatch(t)
	prof := loadCompliantRSIProfile(t)
	lkg := validLKGState()

	// SP01 is a no-new-hardware slice and passes when RSI G1-G7 + S1-S6 pass.
	rec, err := batch.EvaluateSliceCandidate("SP01", "FULL", prof, lkg)
	if err != nil {
		t.Fatalf("EvaluateSliceCandidate SP01: %v", err)
	}
	if rec.Verdict != rsi.VerdictPass || !rec.PromotedToLKG {
		t.Fatalf("expected SP01 to pass and promote to LKG, got verdict=%s blockers=%v", rec.Verdict, rec.Blockers)
	}

	// C27 requires deferred Fork 3 second-provider hardware and must be blocked now.
	recHW, err := batch.EvaluateSliceCandidate("C27", "FULL", prof, lkg)
	if err != nil {
		t.Fatalf("EvaluateSliceCandidate C27: %v", err)
	}
	if recHW.Verdict != rsi.VerdictFail || recHW.PromotedToLKG {
		t.Fatalf("expected deferred Fork 3 slice C27 to be blocked while hardware is deferred")
	}

	// Quarantined SHA (S6) must block promotion even on a no-new-hardware slice.
	badLKG := validLKGState()
	badLKG.CandidateSHA = "deadbeef00000000000000000000000000000000"
	recQ, err := batch.EvaluateSliceCandidate("SP01", "FULL", prof, badLKG)
	if err != nil {
		t.Fatalf("EvaluateSliceCandidate quarantined: %v", err)
	}
	if recQ.Verdict != rsi.VerdictFail || recQ.PromotedToLKG {
		t.Fatalf("expected quarantined SHA to fail S6 gate")
	}
}
