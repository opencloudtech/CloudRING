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
		if rep.Passed+rep.Failed != len(rep.Checks) {
			t.Fatalf("check count mismatch: passed=%d failed=%d total=%d", rep.Passed, rep.Failed, len(rep.Checks))
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
