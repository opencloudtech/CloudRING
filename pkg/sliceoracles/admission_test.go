// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package sliceoracles_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/rsi"
	"github.com/opencloudtech/CloudRING/pkg/sliceoracles"
)

func TestDeclaredAutonomyClassCoversAllowedPaths(t *testing.T) {
	batch := loadCanonicalBatch(t)
	rank := map[string]int{rsi.ClassK0: 0, rsi.ClassK1: 1, rsi.ClassK2: 2, rsi.ClassK3: 3, rsi.ClassK4: 4}
	for _, o := range batch.Oracles {
		cls, err := rsi.ClassifyCandidate(rsi.CandidateMetadata{ID: o.SliceID, DeclaredClass: o.AutonomyClass, ChangedPaths: o.AllowedPaths})
		if err != nil {
			t.Fatalf("%s: %v", o.SliceID, err)
		}
		if rank[o.AutonomyClass] < rank[cls.EffectiveClass] {
			t.Errorf("%s declares %s but its allowedPaths are %s (%v)", o.SliceID, o.AutonomyClass, cls.EffectiveClass, cls.EscalationReasons)
		}
	}

	// A batch that declares a slice below its effective class is rejected.
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "slice-oracles", "oracles-32.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, o := range doc["oracles"].([]any) {
		if o := o.(map[string]any); o["sliceId"] == "SP01" {
			o["autonomyClass"] = rsi.ClassK3
		}
	}
	lowered, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sliceoracles.ParseBatch(lowered); err == nil {
		t.Fatal("batch declaring SP01 as K3 with a .github allowed path was accepted")
	}
}

func TestMergeAdmissionSkipsLKGPromotion(t *testing.T) {
	batch := loadCanonicalBatch(t)
	read := func(name string) rsi.CandidateProfile {
		data, err := os.ReadFile(filepath.Join("..", "..", "contracts", "rsi-governance", "fixtures", name))
		if err != nil {
			t.Fatal(err)
		}
		prof, err := rsi.ParseProfile(data)
		if err != nil {
			t.Fatal(err)
		}
		return prof
	}
	noLKG := sliceoracles.LKGSafetyState{}

	rec, err := batch.EvaluateSliceCandidate("C06", "FULL", read("merge-only-k3-profile.json"), noLKG)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Verdict != rsi.VerdictPass || rec.PromotedToLKG || len(rec.Blockers) != 0 {
		t.Fatalf("merge admission: verdict=%s promoted=%t blockers=%v", rec.Verdict, rec.PromotedToLKG, rec.Blockers)
	}

	// The slot state passed to slice acceptance replaces the profile's own LKG
	// receipt, so a profile cannot vouch for a slot it is not promoted into.
	rec, err = batch.EvaluateSliceCandidate("C06", "FULL", read("compliant-k3-profile.json"), noLKG)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Verdict != rsi.VerdictFail || rec.PromotedToLKG || len(rec.Blockers) != 8 || rec.RSIReport == nil || rec.RSIReport.Verdict != rsi.VerdictFail {
		t.Fatalf("deploy admission without LKG state: verdict=%s promoted=%t blockers=%v", rec.Verdict, rec.PromotedToLKG, rec.Blockers)
	}
	for _, c := range rec.RSIReport.Checks {
		if c.ID == "s1_s6_lkg_promotion" && c.Status != rsi.StatusFail {
			t.Fatalf("s1_s6_lkg_promotion %s for an empty slot", c.Status)
		}
	}
}

// A merge claim that contradicts its own scope is evaluated as deploy, and its
// S1-S6 check then runs against the slot passed to slice acceptance, never
// against the receipt the profile carries about itself.
func TestContradictedMergeIsCheckedAgainstTheSlot(t *testing.T) {
	batch := loadCanonicalBatch(t)
	read := func(name string) rsi.CandidateProfile {
		data, err := os.ReadFile(filepath.Join("..", "..", "contracts", "rsi-governance", "fixtures", name))
		if err != nil {
			t.Fatal(err)
		}
		prof, err := rsi.ParseProfile(data)
		if err != nil {
			t.Fatal(err)
		}
		return prof
	}
	goodSlot := *read("compliant-k3-profile.json").LKG
	s1s6 := func(rec *sliceoracles.SliceAcceptanceReceipt) rsi.CheckResult {
		t.Helper()
		if rec.RSIReport == nil || rec.RSIReport.Admission != rsi.AdmissionDeploy {
			t.Fatalf("contradicted merge was not evaluated as deploy: %+v", rec.RSIReport)
		}
		for _, c := range rec.RSIReport.Checks {
			if c.ID == "s1_s6_lkg_promotion" {
				return c
			}
		}
		t.Fatal("no s1_s6_lkg_promotion check")
		return rsi.CheckResult{}
	}

	selfVouching := read("merge-only-k3-profile.json")
	selfVouching.LKG = &goodSlot
	rec, err := batch.EvaluateSliceCandidate("C06", "FULL", selfVouching, sliceoracles.LKGSafetyState{})
	if err != nil {
		t.Fatal(err)
	}
	if c := s1s6(rec); c.Status != rsi.StatusFail || rec.Verdict != rsi.VerdictFail || rec.PromotedToLKG {
		t.Fatalf("own receipt vouched for an empty slot: s1_s6=%s %q verdict=%s", c.Status, c.Summary, rec.Verdict)
	}

	withTarget := read("merge-only-k3-profile.json")
	withTarget.Candidate.DeploymentTargets = []string{"hub"}
	rec, err = batch.EvaluateSliceCandidate("C06", "FULL", withTarget, goodSlot)
	if err != nil {
		t.Fatal(err)
	}
	if c := s1s6(rec); c.Status != rsi.StatusPass {
		t.Fatalf("contradicted merge ignored the supplied slot: s1_s6=%s %q", c.Status, c.Summary)
	}
	rec, err = batch.EvaluateSliceCandidate("C06", "FULL", withTarget, sliceoracles.LKGSafetyState{})
	if err != nil {
		t.Fatal(err)
	}
	if c := s1s6(rec); c.Status != rsi.StatusFail || len(rec.Blockers) < 6 {
		t.Fatalf("contradicted merge with an empty slot: s1_s6=%s blockers=%v", c.Status, rec.Blockers)
	}
}
