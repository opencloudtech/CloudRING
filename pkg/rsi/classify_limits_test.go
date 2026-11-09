// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package rsi

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// Each case changes one path or flag so that every escalation rule decides the
// class (and the reasons) on its own.
func TestClassifyCandidateEscalationRules(t *testing.T) {
	cases := []struct {
		name     string
		meta     CandidateMetadata
		want     string
		wantWhy  []string
		readOnly bool
	}{
		{"backslash path", CandidateMetadata{DeclaredClass: ClassK1, ChangedPaths: []string{`a\b.go`}}, ClassK4, []string{`invalid_or_backslash_path:a\b.go`}, false},
		{"blank path", CandidateMetadata{DeclaredClass: ClassK1, ChangedPaths: []string{"  "}}, ClassK4, []string{"invalid_or_backslash_path:  "}, false},
		{"absolute path", CandidateMetadata{DeclaredClass: ClassK1, ChangedPaths: []string{"/etc/passwd"}}, ClassK4, []string{"path_traversal_or_absolute:/etc/passwd"}, false},
		{"repository root", CandidateMetadata{DeclaredClass: ClassK1, ReversibleConfigOnly: true, ChangedPaths: []string{"./"}}, ClassK4, []string{"path_traversal_or_absolute:./"}, false},
		{"rsi package root", CandidateMetadata{DeclaredClass: ClassK1, ReversibleConfigOnly: true, ChangedPaths: []string{"pkg/rsi"}}, ClassK3, []string{"touches_ai_or_rsi_layer_requires_k3"}, false},
		{"nested rsi dir", CandidateMetadata{DeclaredClass: ClassK1, ReversibleConfigOnly: true, ChangedPaths: []string{"docs/rsi/notes.md"}}, ClassK3, []string{"touches_ai_or_rsi_layer_requires_k3"}, false},
		{"skills", CandidateMetadata{DeclaredClass: ClassK1, ReversibleConfigOnly: true, ChangedPaths: []string{"skills/a.md"}}, ClassK3, []string{"touches_ai_or_rsi_layer_requires_k3"}, false},
		{"agents", CandidateMetadata{DeclaredClass: ClassK1, ReversibleConfigOnly: true, ChangedPaths: []string{"agents/a.md"}}, ClassK3, []string{"touches_ai_or_rsi_layer_requires_k3"}, false},
		{"prompts", CandidateMetadata{DeclaredClass: ClassK1, ReversibleConfigOnly: true, ChangedPaths: []string{"prompts/a.txt"}}, ClassK3, []string{"touches_ai_or_rsi_layer_requires_k3"}, false},
		{"reversible docs", CandidateMetadata{DeclaredClass: ClassK1, ReversibleConfigOnly: true, ChangedPaths: []string{"docs/a.md"}}, ClassK1, nil, false},
		{"testdata file", CandidateMetadata{DeclaredClass: ClassK2, ModifiedTestdata: true, ChangedPaths: []string{"pkg/x/testdata/a.json"}}, ClassK4, []string{"modified_testdata_fixtures_requires_k4"}, false},
		{"testdata dir", CandidateMetadata{DeclaredClass: ClassK2, ModifiedTestdata: true, ChangedPaths: []string{"pkg/x/testdata"}}, ClassK4, []string{"modified_testdata_fixtures_requires_k4"}, false},
		{"test file with testdata", CandidateMetadata{DeclaredClass: ClassK2, ModifiedTestdata: true, ChangedPaths: []string{"pkg/x/a_test.go"}}, ClassK4, []string{"modified_testdata_fixtures_requires_k4"}, false},
		{"test file only", CandidateMetadata{DeclaredClass: ClassK2, ChangedPaths: []string{"pkg/x/a_test.go"}}, ClassK2, nil, false},
		{"go file outside code roots", CandidateMetadata{DeclaredClass: ClassK1, ReversibleConfigOnly: true, ChangedPaths: []string{"tools/x.go"}}, ClassK2, nil, false},
		{"cmd config", CandidateMetadata{DeclaredClass: ClassK1, ReversibleConfigOnly: true, ChangedPaths: []string{"cmd/x.yaml"}}, ClassK2, nil, false},
		{"pkg config", CandidateMetadata{DeclaredClass: ClassK1, ReversibleConfigOnly: true, ChangedPaths: []string{"pkg/x.yaml"}}, ClassK2, nil, false},
		{"read-only production", CandidateMetadata{DeclaredClass: ClassK0, ChangedPaths: []string{"pkg/x.go"}}, ClassK0, nil, true},
		{"writable K0 docs", CandidateMetadata{DeclaredClass: ClassK0, ReversibleConfigOnly: true, ChangedPaths: []string{"docs/a.md"}}, ClassK1, nil, false},
		{"declared K3 docs", CandidateMetadata{DeclaredClass: ClassK3, ReversibleConfigOnly: true, ChangedPaths: []string{"docs/a.md"}}, ClassK3, nil, false},
		{"irreversible docs", CandidateMetadata{DeclaredClass: ClassK1, ChangedPaths: []string{"docs/a.md"}}, ClassK2, nil, false},
		{"declared K3 production", CandidateMetadata{DeclaredClass: ClassK3, ChangedPaths: []string{"pkg/x.go"}}, ClassK3, nil, false},
		{"declared K2 docs", CandidateMetadata{DeclaredClass: ClassK2, ChangedPaths: []string{"docs/a.md"}}, ClassK2, nil, false},
		{"declared K3 ai path", CandidateMetadata{DeclaredClass: ClassK3, ChangedPaths: []string{"pkg/rsi/x.go"}}, ClassK3, nil, false},
		{"declared K4 ai path", CandidateMetadata{DeclaredClass: ClassK4, ChangedPaths: []string{"pkg/rsi/x.go"}}, ClassK4, nil, false},
		{"duplicate protected path", CandidateMetadata{DeclaredClass: ClassK1, ChangedPaths: []string{".github/x", ".github/x"}}, ClassK4, []string{"protected_k4_path:.github/x"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.meta.ID = "c"
			tc.meta.ReadOnlyOnly = tc.readOnly
			cls, err := ClassifyCandidate(tc.meta)
			if err != nil {
				t.Fatal(err)
			}
			want := tc.wantWhy
			if want == nil {
				want = []string{}
			}
			if cls.EffectiveClass != tc.want || !slices.Equal(cls.EscalationReasons, want) {
				t.Fatalf("got %s %q, want %s %q", cls.EffectiveClass, cls.EscalationReasons, tc.want, want)
			}
		})
	}
}

func TestParseProfileSizeAndKind(t *testing.T) {
	raw, err := json.Marshal(validCompliantK3Profile())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseProfile(nil); !errors.Is(err, ErrInvalidProfile) || !strings.Contains(err.Error(), "size out of bounds") {
		t.Fatalf("empty profile: %v", err)
	}
	exact := append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), maxProfileBytes-len(raw))...)
	if _, err := ParseProfile(exact); err != nil {
		t.Fatalf("profile of exactly %d bytes rejected: %v", maxProfileBytes, err)
	}
	if _, err := ParseProfile(append(exact, ' ')); err == nil || !strings.Contains(err.Error(), "size out of bounds") {
		t.Fatalf("profile of %d bytes: %v", maxProfileBytes+1, err)
	}
	for name, edit := range map[string]func(*CandidateProfile){
		"wrong kind":       func(p *CandidateProfile) { p.Kind = "Other" },
		"wrong apiVersion": func(p *CandidateProfile) { p.APIVersion = "other/v1" },
	} {
		p := validCompliantK3Profile()
		edit(&p)
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseProfile(data); err == nil || !strings.Contains(err.Error(), "expected apiVersion") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// k1Profile and k2Profile are deploy candidates whose effective class is K1
// (reversible docs) and K2 (non-AI production code).
func k1Profile() CandidateProfile {
	p := validCompliantK3Profile()
	p.Candidate.DeclaredClass = ClassK1
	p.Candidate.ReversibleConfigOnly = true
	p.Candidate.ChangedPaths = []string{"docs/a.md"}
	return p
}

func k2Profile() CandidateProfile {
	p := validCompliantK3Profile()
	p.Candidate.DeclaredClass = ClassK2
	p.Candidate.ChangedPaths = []string{"pkg/x/y.go"}
	return p
}

func TestRedGreenRequiredFromK2(t *testing.T) {
	for name, p := range map[string]CandidateProfile{"K1": k1Profile(), "K2": k2Profile()} {
		p.Gates.G1.NewTestFailedBeforeFix, p.Gates.G1.NewTestPassedAfterFix = false, false
		rep := evaluate(t, p)
		if rep.Classification.EffectiveClass != name {
			t.Fatalf("%s profile classified %s", name, rep.Classification.EffectiveClass)
		}
		want := StatusPass
		if name == "K2" {
			want = StatusFail
		}
		if got := checkStatus(rep, "g1_red_green_and_test_integrity"); got != want {
			t.Errorf("%s without red-green: g1 %s, want %s", name, got, want)
		}
	}
}

func TestMutationScoreLimits(t *testing.T) {
	cases := []struct {
		name          string
		profile       CandidateProfile
		killed, total int
		status, ratio string
	}{
		{"K2 without mutants", k2Profile(), 0, 0, StatusFail, "0"},
		{"K3 without mutants", validCompliantK3Profile(), 0, 0, StatusFail, "0"},
		{"K3 negative killed", validCompliantK3Profile(), -1, 10, StatusFail, "0"},
		{"K3 killed above total", validCompliantK3Profile(), 12, 10, StatusFail, "0"},
		{"K3 all killed", validCompliantK3Profile(), 10, 10, StatusPass, "1"},
		{"K3 at threshold", validCompliantK3Profile(), 4, 5, StatusPass, "4/5"},
		{"K3 below threshold", validCompliantK3Profile(), 79, 100, StatusFail, "79/100"},
		{"K1 half killed", k1Profile(), 5, 10, StatusPass, "1/2"},
		{"K1 all killed", k1Profile(), 10, 10, StatusPass, "1"},
		{"K1 none killed", k1Profile(), 0, 10, StatusPass, "0"},
		{"K1 without mutants", k1Profile(), 0, 0, StatusPass, "0"},
		{"K1 negative killed", k1Profile(), -1, 10, StatusPass, "0"},
		{"K1 killed above total", k1Profile(), 11, 10, StatusPass, "0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.profile
			p.Gates.G2.KilledMutants, p.Gates.G2.TotalMutants = tc.killed, tc.total
			rep := evaluate(t, p)
			if got := checkStatus(rep, "g2_diff_mutation_and_fuzz"); got != tc.status || rep.MutationKillRatio != tc.ratio {
				t.Fatalf("g2 %s ratio %s, want %s ratio %s", got, rep.MutationKillRatio, tc.status, tc.ratio)
			}
		})
	}
}

func TestG3EveryConditionIsRequired(t *testing.T) {
	for name, edit := range map[string]func(*G3Receipt){
		"one SAST finding":          func(g *G3Receipt) { g.SASTFindings = 1 },
		"one vulnerability":         func(g *G3Receipt) { g.VulnFindings = 1 },
		"no external capability":    func(g *G3Receipt) { g.ExternalCapabilityGate = false },
		"delimiter-only security":   func(g *G3Receipt) { g.PromptDelimiterOnlySecurity = true },
		"explanation-only approval": func(g *G3Receipt) { g.ExplanationOnlyApproval = true },
	} {
		p := validCompliantK3Profile()
		edit(&p.Gates.G3)
		if got := checkStatus(evaluate(t, p), "g3_security_and_capability_boundary"); got != StatusFail {
			t.Errorf("%s: g3 %s", name, got)
		}
	}
	if got := checkStatus(evaluate(t, validCompliantK3Profile()), "g3_security_and_capability_boundary"); got != StatusPass {
		t.Fatalf("clean G3 receipt: %s", got)
	}
}

func TestUnapprovedK4WithoutTestTamperingTripsNoKillSwitch(t *testing.T) {
	p := validCompliantK3Profile()
	p.Candidate.ChangedPaths = append(p.Candidate.ChangedPaths, ".github/x.json")
	rep := evaluate(t, p)
	if checkStatus(rep, "k4_human_boundary") != StatusFail || rep.KillSwitchLevel != KillSwitchNone || len(rep.KillSwitchReasons) != 0 {
		t.Fatalf("k4=%s killSwitch=%s %v", checkStatus(rep, "k4_human_boundary"), rep.KillSwitchLevel, rep.KillSwitchReasons)
	}
	p.Candidate.DeletedOrSkippedTests = 1
	if rep = evaluate(t, p); rep.KillSwitchLevel != KillSwitchL3 {
		t.Fatalf("deleted test under unapproved K4: killSwitch=%s", rep.KillSwitchLevel)
	}
}

func TestRationalFieldsRejectNegativeAndMalformedValues(t *testing.T) {
	for _, value := range []string{"-1", "-0.5", "abc", "1/0"} {
		p := validCompliantK3Profile()
		p.Gates.G4.CanaryStepPercent = value
		if _, err := EvaluateCandidate(p); !errors.Is(err, ErrInvalidProfile) {
			t.Errorf("canaryStepPercent %q: %v", value, err)
		}
	}
	for _, value := range []string{"1", "1/1", "0"} {
		p := validCompliantK3Profile()
		p.VOI.TestSensitivity = value
		p.VOI.TestSpecificity = "3/4"
		if value == "0" {
			// A test that never fires is degenerate; only the bound is checked here.
			p.VOI.TestSpecificity = "1/2"
		}
		if _, err := EvaluateCandidate(p); err != nil {
			t.Errorf("testSensitivity %q rejected: %v", value, err)
		}
	}
	p := validCompliantK3Profile()
	p.VOI.TestSensitivity = "11/10"
	if _, err := EvaluateCandidate(p); !errors.Is(err, ErrInvalidProfile) {
		t.Errorf("testSensitivity above 1 accepted: %v", err)
	}
}
