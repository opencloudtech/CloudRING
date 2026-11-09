// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package rsi

import (
	"encoding/json"
	"testing"
)

func FuzzEvaluateCandidate(f *testing.F) {
	prof := validCompliantK3Profile()
	seedPass, err := json.Marshal(prof)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seedPass)

	profFail := validCompliantK3Profile()
	profFail.Candidate.ChangedPaths = []string{".github/workflows/ci.yml"}
	profFail.Candidate.DeletedOrSkippedTests = 1
	seedFail, err := json.Marshal(profFail)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seedFail)
	seedMerge, err := json.Marshal(mergeOnlyProfile())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seedMerge)
	f.Add([]byte(`{"apiVersion":"cloudring.org/rsi-governance/v1","kind":"RSICandidateProfile"}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		parsed, err := ParseProfile(raw)
		if err != nil {
			return
		}
		rep, err := EvaluateCandidate(parsed)
		if err != nil {
			return
		}
		if rep.Passed+rep.Failed+rep.NotApplicable != len(rep.Checks) {
			t.Fatalf("check count mismatch: passed=%d failed=%d notApplicable=%d total=%d", rep.Passed, rep.Failed, rep.NotApplicable, len(rep.Checks))
		}
		merge := rep.Admission == AdmissionMerge
		c := parsed.Candidate
		if merge && (c.Admission != AdmissionMerge || len(c.DeploymentTargets) > 0 || parsed.Gates.G4 != (G4Receipt{}) || parsed.LKG != nil ||
			!mergeOnlyTargets[mergeTarget{c.TargetRepository, c.TargetBranch}]) {
			t.Fatalf("candidate with deployment evidence evaluated as merge: %+v", c)
		}
		seen := map[string]bool{}
		for _, check := range rep.Checks {
			seen[check.ID] = true
			if check.Status == StatusNotApplicable && !merge &&
				(check.ID == "g4_canary_slo_and_stateful_downgrade" || check.ID == "s1_s6_lkg_promotion" || check.ID == "g7_budget_and_cross_family_overseer") {
				t.Fatalf("deploy-time check %s skipped for admission %s", check.ID, rep.Admission)
			}
		}
		if !seen["s1_s6_lkg_promotion"] {
			t.Fatalf("report has no s1_s6_lkg_promotion check: %+v", rep.Checks)
		}
		g6 := parsed.Gates.G6
		g6Valid := g6.AIFailedDeployments >= 0 && g6.HumanFailedDeployments >= 0 && g6.HumanFailedDeployments <= g6.HumanTotalDeployments
		if !merge && g6Valid && g6.AITotalDeployments == 0 && g6.AIFailedDeployments == 0 && rep.Classification.EffectiveClass != ClassK4 {
			t.Fatalf("deploy cold start not escalated to K4: %+v", rep.Classification)
		}
		if rep.Verdict == VerdictPass && rep.Classification.EffectiveClass == ClassK4 && !validReference(c.HumanK4ApprovalReference) {
			t.Fatalf("K4 candidate passed without a valid human reference %q", c.HumanK4ApprovalReference)
		}
		if rep.Failed > 0 && rep.Verdict != VerdictFail {
			t.Fatalf("failed checks=%d but verdict=%s", rep.Failed, rep.Verdict)
		}
		if rep.Failed == 0 && rep.Verdict != VerdictPass {
			t.Fatalf("zero failed checks but verdict=%s", rep.Verdict)
		}
		if rep.Classification.EffectiveClass == ClassK4 && strings_trim(parsed.Candidate.HumanK4ApprovalReference) == "" && rep.Verdict == VerdictPass {
			t.Fatalf("unapproved K4 candidate must never pass: %+v", rep)
		}
	})
}

func strings_trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
