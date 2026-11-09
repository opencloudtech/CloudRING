// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package rsi

import (
	"encoding/json"
	"strings"
	"testing"
)

// mergeOnlyProfile is a K3 candidate merged into public main, which deploys
// nothing, directed by an operator and carrying no deployment, drill, history,
// budget or LKG receipt.
func mergeOnlyProfile() CandidateProfile {
	p := validCompliantK3Profile()
	p.Candidate.Admission = AdmissionMerge
	p.Candidate.TargetRepository = "opencloudtech/CloudRING"
	p.Candidate.TargetBranch = "main"
	p.Candidate.Origin = OriginOperatorDirected
	p.Candidate.OperatorReference = "review-1"
	p.Gates.G4 = G4Receipt{}
	p.Gates.G5 = G5Receipt{}
	p.Gates.G6 = G6Receipt{}
	p.Gates.G7 = G7Receipt{}
	p.LKG = nil
	p.VOI, p.PassK, p.Experiment, p.Discovery = nil, nil, nil, nil
	return p
}

func evaluate(t *testing.T, p CandidateProfile) Report {
	t.Helper()
	rep, err := EvaluateCandidate(p)
	if err != nil {
		t.Fatalf("EvaluateCandidate: %v", err)
	}
	return rep
}

func checkOf(rep Report, id string) CheckResult {
	for _, c := range rep.Checks {
		if c.ID == id {
			return c
		}
	}
	return CheckResult{ID: id, Status: "missing"}
}

func checkStatus(rep Report, id string) string {
	return checkOf(rep, id).Status
}

func TestMergeAdmissionPassesWithoutDeploymentEvidence(t *testing.T) {
	rep := evaluate(t, mergeOnlyProfile())
	if rep.Verdict != VerdictPass || rep.Admission != AdmissionMerge || rep.Failed != 0 || rep.KillSwitchLevel != KillSwitchNone {
		t.Fatalf("merge-only candidate: verdict=%s admission=%s failed=%d kill=%s checks=%+v", rep.Verdict, rep.Admission, rep.Failed, rep.KillSwitchLevel, rep.Checks)
	}
	for _, id := range []string{"g4_canary_slo_and_stateful_downgrade", "g5_portability_and_switching_drill",
		"g6_dora_cfr_circuit_breaker", "g7_budget_and_cross_family_overseer", "s1_s6_lkg_promotion"} {
		if got := checkStatus(rep, id); got != StatusNotApplicable {
			t.Errorf("%s: status %s, want %s", id, got, StatusNotApplicable)
		}
	}
	if rep.NotApplicable != 5 || rep.Passed+rep.Failed+rep.NotApplicable != len(rep.Checks) {
		t.Fatalf("check accounting: passed=%d failed=%d notApplicable=%d checks=%d", rep.Passed, rep.Failed, rep.NotApplicable, len(rep.Checks))
	}
	if got := checkOf(rep, "admission_scope_consistency").Summary; !strings.Contains(got, "target=opencloudtech/CloudRING@main") {
		t.Fatalf("scope summary does not name the merge target: %q", got)
	}

	// Supplied evidence is never ignored: a failed drill or a tripped breaker fails a merge too.
	p := mergeOnlyProfile()
	p.Gates.G5 = G5Receipt{PortabilityDrillPassed: false, DataActVerdict: VerdictFail}
	if rep := evaluate(t, p); rep.Verdict != VerdictFail || checkStatus(rep, "g5_portability_and_switching_drill") != StatusFail {
		t.Fatalf("supplied failing G5 receipt was not evaluated: %+v", rep.Checks)
	}
	p = mergeOnlyProfile()
	p.Gates.G6 = G6Receipt{AIFailedDeployments: 4, AITotalDeployments: 20}
	if rep := evaluate(t, p); rep.Verdict != VerdictFail || rep.MaxAutonomousClass != ClassK1 || rep.KillSwitchLevel != KillSwitchL1 {
		t.Fatalf("AI CFR 4/20 must trip the breaker for a merge: verdict=%s maxAuto=%s kill=%s", rep.Verdict, rep.MaxAutonomousClass, rep.KillSwitchLevel)
	}
}

func TestDeployAdmissionAppliesEveryGate(t *testing.T) {
	for _, admission := range []string{"", AdmissionDeploy} {
		p := mergeOnlyProfile()
		p.Candidate.Admission = admission
		p.Candidate.DeploymentTargets = []string{"hub"}
		rep := evaluate(t, p)
		if rep.Verdict != VerdictFail || rep.Admission != AdmissionDeploy || rep.NotApplicable != 0 {
			t.Fatalf("admission %q: verdict=%s admission=%s notApplicable=%d", admission, rep.Verdict, rep.Admission, rep.NotApplicable)
		}
		// An operator-directed deployment without receipts fails G4, G5, G7 and S1-S6.
		for _, id := range []string{"g4_canary_slo_and_stateful_downgrade", "g5_portability_and_switching_drill",
			"g7_budget_and_cross_family_overseer", "s1_s6_lkg_promotion"} {
			if got := checkStatus(rep, id); got != StatusFail {
				t.Errorf("admission %q: %s status %s, want %s", admission, id, got, StatusFail)
			}
		}
	}
	// The full deploy receipt of the compliant profile still passes unchanged.
	rep := evaluate(t, validCompliantK3Profile())
	if rep.Verdict != VerdictPass || rep.Admission != AdmissionDeploy || rep.NotApplicable != 0 || checkStatus(rep, "s1_s6_lkg_promotion") != StatusPass {
		t.Fatalf("compliant deploy profile: verdict=%s admission=%s notApplicable=%d checks=%+v", rep.Verdict, rep.Admission, rep.NotApplicable, rep.Checks)
	}
}

func TestDeployAdmissionEvaluatesLKGReceipt(t *testing.T) {
	p := validCompliantK3Profile()
	p.LKG = nil
	rep := evaluate(t, p)
	if rep.Verdict != VerdictFail || checkStatus(rep, "s1_s6_lkg_promotion") != StatusFail {
		t.Fatalf("deploy without LKG receipt: verdict=%s checks=%+v", rep.Verdict, rep.Checks)
	}

	p = validCompliantK3Profile()
	p.LKG.CandidateSHA = p.LKG.QuarantinedSHAs[0]
	rep = evaluate(t, p)
	if c := checkOf(rep, "s1_s6_lkg_promotion"); rep.Verdict != VerdictFail || c.Status != StatusFail || !strings.HasPrefix(c.Summary, "S6: ") {
		t.Fatalf("quarantined candidate SHA: verdict=%s check=%+v", rep.Verdict, c)
	}

	p = validCompliantK3Profile()
	p.LKG = &LKGReceipt{}
	if blockers := ValidateLKG(*p.LKG); len(blockers) != 7 {
		t.Fatalf("empty LKG receipt: %d blockers, want 7: %v", len(blockers), blockers)
	}
	if rep := evaluate(t, p); rep.Verdict != VerdictFail || checkStatus(rep, "s1_s6_lkg_promotion") != StatusFail {
		t.Fatalf("empty LKG receipt passed: %+v", rep.Checks)
	}
}

func TestMislabelledMergeAdmissionFailsClosed(t *testing.T) {
	addPath := func(path string) func(*CandidateProfile) {
		return func(p *CandidateProfile) { p.Candidate.ChangedPaths = append(p.Candidate.ChangedPaths, path) }
	}
	cases := map[string]func(*CandidateProfile){
		"deployment target":      func(p *CandidateProfile) { p.Candidate.DeploymentTargets = []string{"hub"} },
		"deploy manifest":        addPath("deploy/kubernetes/storage/x.yaml"),
		"nested deploy dir":      addPath("reference/synthetic-service/Deploy/kubernetes.yaml"),
		"iac":                    addPath("iac/main.tf"),
		"branch workflow":        addPath(".github/workflows/ci.yml"),
		"traversal":              addPath("pkg/../deploy/x.yaml"),
		"gitlink":                addPath("cloudring_core"),
		"submodule manifest":     addPath(".gitmodules"),
		"canary receipt":         func(p *CandidateProfile) { p.Gates.G4 = validCompliantK3Profile().Gates.G4 },
		"lkg receipt":            func(p *CandidateProfile) { p.LKG = validCompliantK3Profile().LKG },
		"no target":              func(p *CandidateProfile) { p.Candidate.TargetRepository, p.Candidate.TargetBranch = "", "" },
		"gitops repository":      func(p *CandidateProfile) { p.Candidate.TargetRepository = "opencloudtech/cloudring-enterprise" },
		"case-variant target":    func(p *CandidateProfile) { p.Candidate.TargetRepository = "opencloudtech/cloudring" },
		"other branch":           func(p *CandidateProfile) { p.Candidate.TargetBranch = "release" },
		"unknown origin":         func(p *CandidateProfile) { p.Candidate.Origin = "self" },
		"unnamed operator":       func(p *CandidateProfile) { p.Candidate.OperatorReference = " " },
		"zero-width operator":    func(p *CandidateProfile) { p.Candidate.OperatorReference = "\u200b" },
		"nbsp operator":          func(p *CandidateProfile) { p.Candidate.OperatorReference = "\u00a0" },
		"hangul filler operator": func(p *CandidateProfile) { p.Candidate.OperatorReference = "\u3164" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := mergeOnlyProfile()
			mutate(&p)
			rep := evaluate(t, p)
			if rep.Verdict != VerdictFail || rep.Admission != AdmissionDeploy || checkStatus(rep, "admission_scope_consistency") != StatusFail ||
				checkStatus(rep, "g4_canary_slo_and_stateful_downgrade") == StatusNotApplicable ||
				checkStatus(rep, "g7_budget_and_cross_family_overseer") == StatusNotApplicable ||
				checkStatus(rep, "s1_s6_lkg_promotion") == StatusNotApplicable {
				t.Fatalf("mislabelled merge was not evaluated as a failing deployment: admission=%s checks=%+v", rep.Admission, rep.Checks)
			}
		})
	}
	for _, field := range []string{`"admission":"ship"`, `"origin":"self"`} {
		raw := []byte(`{"apiVersion":"cloudring.org/rsi-governance/v1","kind":"RSICandidateProfile","candidate":{"id":"c","declaredClass":"K2","changedPaths":["pkg/x.go"],` + field + `}}`)
		if _, err := ParseProfile(raw); err == nil {
			t.Fatalf("ParseProfile accepted %s", field)
		}
	}
}

func TestDeployColdStartRequiresHumanK4Approval(t *testing.T) {
	coldDeploy := func(approval string) CandidateProfile {
		p := validCompliantK3Profile()
		p.Candidate.HumanK4ApprovalReference = approval
		p.Gates.G6 = G6Receipt{HumanFailedDeployments: 1, HumanTotalDeployments: 10}
		return p
	}
	for _, approval := range []string{"", "\u200b", "\u00a0\u00a0"} {
		rep := evaluate(t, coldDeploy(approval))
		if rep.Classification.EffectiveClass != ClassK4 || !strings.Contains(strings.Join(rep.Classification.EscalationReasons, ","), "deploy_cold_start_requires_k4") ||
			rep.Verdict != VerdictFail || checkStatus(rep, "k4_human_boundary") != StatusFail {
			t.Fatalf("cold-start deploy with approval %q: class=%s reasons=%v verdict=%s checks=%+v",
				approval, rep.Classification.EffectiveClass, rep.Classification.EscalationReasons, rep.Verdict, rep.Checks)
		}
	}
	rep := evaluate(t, coldDeploy("change-42"))
	if rep.Verdict != VerdictPass || rep.Classification.EffectiveClass != ClassK4 || checkStatus(rep, "g6_dora_cfr_circuit_breaker") != StatusPass {
		t.Fatalf("human-approved first AI deployment: verdict=%s class=%s checks=%+v", rep.Verdict, rep.Classification.EffectiveClass, rep.Checks)
	}
	// With AI history a human approval does not bypass the breaker, and the
	// cold-start escalation no longer applies.
	p := coldDeploy("change-42")
	p.Gates.G6.AIFailedDeployments, p.Gates.G6.AITotalDeployments = 4, 20
	rep = evaluate(t, p)
	if rep.Verdict != VerdictFail || rep.MaxAutonomousClass != ClassK1 || strings.Contains(strings.Join(rep.Classification.EscalationReasons, ","), "deploy_cold_start") {
		t.Fatalf("approval bypassed an existing CFR breach: verdict=%s maxAuto=%s reasons=%v", rep.Verdict, rep.MaxAutonomousClass, rep.Classification.EscalationReasons)
	}
	rep = evaluate(t, mergeOnlyProfile())
	if checkStatus(rep, "g6_dora_cfr_circuit_breaker") != StatusNotApplicable || rep.Classification.EffectiveClass != ClassK3 {
		t.Fatalf("merge cold start: class=%s checks=%+v", rep.Classification.EffectiveClass, rep.Checks)
	}
}

func TestG7SkipsOnlyOperatorDirectedMerge(t *testing.T) {
	for _, origin := range []string{"", OriginAutonomousLoop} {
		p := mergeOnlyProfile()
		p.Candidate.Origin = origin
		if rep := evaluate(t, p); rep.Verdict != VerdictFail || checkStatus(rep, "g7_budget_and_cross_family_overseer") != StatusFail {
			t.Fatalf("origin %q without budget receipt: checks=%+v", origin, rep.Checks)
		}
	}
	// An operator-directed deployment is still bounded by G7.
	p := validCompliantK3Profile()
	p.Candidate.Origin = OriginOperatorDirected
	p.Candidate.OperatorReference = "review-1"
	p.Gates.G7 = G7Receipt{}
	if rep := evaluate(t, p); rep.Verdict != VerdictFail || checkStatus(rep, "g7_budget_and_cross_family_overseer") != StatusFail {
		t.Fatalf("operator-directed deploy without budget receipt: checks=%+v", rep.Checks)
	}
	p = mergeOnlyProfile()
	p.Gates.G7 = validCompliantK3Profile().Gates.G7
	p.Gates.G7.OverseerModelFamily = p.Gates.G7.ExecutorModelFamily
	if rep := evaluate(t, p); rep.Verdict != VerdictFail || checkStatus(rep, "g7_budget_and_cross_family_overseer") != StatusFail {
		t.Fatalf("supplied same-family G7 receipt was not evaluated: %+v", rep.Checks)
	}
}

func TestEvaluatorBootstrapOnlyAdmitsMerge(t *testing.T) {
	p := mergeOnlyProfile()
	p.Candidate.EvaluatorBootstrap = true
	p.Gates.G1.EvaluatorFrozenHashVerified = false
	rep := evaluate(t, p)
	if rep.Classification.EffectiveClass != ClassK4 || rep.Verdict != VerdictFail || rep.Failed != 1 || checkStatus(rep, "k4_human_boundary") != StatusFail {
		t.Fatalf("unapproved evaluator bootstrap: class=%s verdict=%s failed=%d checks=%+v", rep.Classification.EffectiveClass, rep.Verdict, rep.Failed, rep.Checks)
	}
	p.Candidate.HumanK4ApprovalReference = "approval-7"
	if rep := evaluate(t, p); rep.Verdict != VerdictPass {
		t.Fatalf("approved evaluator bootstrap merge: checks=%+v", rep.Checks)
	}

	// A deployment is judged by a frozen evaluator: bootstrap does not stand in for the hash.
	d := validCompliantK3Profile()
	d.Candidate.EvaluatorBootstrap = true
	d.Candidate.HumanK4ApprovalReference = "approval-7"
	d.Gates.G1.EvaluatorFrozenHashVerified = false
	rep = evaluate(t, d)
	if rep.Verdict != VerdictFail || checkStatus(rep, "g1_red_green_and_test_integrity") != StatusFail || checkStatus(rep, "k4_human_boundary") != StatusPass {
		t.Fatalf("deploy with evaluator bootstrap and no frozen hash: verdict=%s checks=%+v", rep.Verdict, rep.Checks)
	}
	d.Gates.G1.EvaluatorFrozenHashVerified = true
	if rep := evaluate(t, d); rep.Verdict != VerdictPass {
		t.Fatalf("approved deploy with a frozen evaluator: checks=%+v", rep.Checks)
	}
}

// profileJSON marshals p, applies edit to its generic JSON tree and returns the bytes.
func profileJSON(t *testing.T, p CandidateProfile, edit func(map[string]any)) []byte {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var tree map[string]any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	edit(tree)
	out, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseProfileRejectsCaseVariantAndUnknownKeys(t *testing.T) {
	obj := func(tree map[string]any, keys ...string) map[string]any {
		for _, k := range keys {
			tree = tree[k].(map[string]any)
		}
		return tree
	}
	deploy := validCompliantK3Profile()
	cases := map[string]struct {
		profile CandidateProfile
		edit    func(map[string]any)
	}{
		"candidate case variant hides targets": {mergeOnlyProfile(), func(m map[string]any) {
			obj(m, "candidate")["DeploymentTargets"] = []any{"hub"}
		}},
		"case variant admission alone": {deploy, func(m map[string]any) {
			c := obj(m, "candidate")
			delete(c, "admission")
			c["Admission"] = "merge"
		}},
		"gates case variant zeroes g4": {deploy, func(m map[string]any) { obj(m, "gates")["G4"] = map[string]any{} }},
		"nested g4 field case variant": {deploy, func(m map[string]any) { obj(m, "gates", "g4")["CanaryStepPercent"] = "50" }},
		"lkg field case variant":       {deploy, func(m map[string]any) { obj(m, "lkg")["CandidateSHA"] = "0" }},
		"array element case variant": {deploy, func(m map[string]any) {
			obj(m, "passK")["tasks"].([]any)[0].(map[string]any)["TaskId"] = "t9"
		}},
		"top-level case variant": {deploy, func(m map[string]any) { m["LKG"] = map[string]any{} }},
		"unknown key":            {deploy, func(m map[string]any) { obj(m, "candidate")["notes"] = "x" }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseProfile(profileJSON(t, tc.profile, tc.edit)); err == nil {
				t.Fatal("ParseProfile accepted a key that is not an exact field name")
			}
		})
	}
	for _, p := range []CandidateProfile{deploy, mergeOnlyProfile()} {
		if _, err := ParseProfile(profileJSON(t, p, func(map[string]any) {})); err != nil {
			t.Fatalf("ParseProfile rejected an exact profile: %v", err)
		}
	}
}

func TestReferencesMustNameARecord(t *testing.T) {
	// Invisible text: zero-width and bidi format characters, no-break spaces,
	// control characters, Hangul fillers (default-ignorable letters), the
	// combining grapheme joiner, variation selectors and the Egyptian
	// hieroglyph blanks (letters that render as empty space).
	invisible := []string{
		"\u200b", "\u00a0", "\u00a0\u00a0", "a\u200bb", "x\u0007", "\u202eabc", "-", " ",
		"\u115f", "\u1160", "\u3164", "\uffa0", "\u3164\u3164", "a\u3164", "\u034f", "\ufe0f", "a\ufe0f", "\u180b", "\U000e0100",
		"\U00013441", "\U00013442", "a\U00013441", "\U00013441\U00013442",
	}
	for _, ref := range invisible {
		for _, field := range []string{"operatorReference", "humanK4ApprovalReference"} {
			raw := profileJSON(t, mergeOnlyProfile(), func(m map[string]any) { m["candidate"].(map[string]any)[field] = ref })
			if _, err := ParseProfile(raw); err == nil {
				t.Errorf("ParseProfile accepted %s %q", field, ref)
			}
		}
		p := mergeOnlyProfile()
		p.Candidate.EvaluatorBootstrap = true
		p.Candidate.HumanK4ApprovalReference = ref
		if rep := evaluate(t, p); checkStatus(rep, "k4_human_boundary") != StatusFail {
			t.Errorf("K4 approved by reference %q", ref)
		}
	}
	for _, ref := range []string{"opencloudtech/CloudRING#168", "change-42", "Ж1"} {
		raw := profileJSON(t, mergeOnlyProfile(), func(m map[string]any) {
			m["candidate"].(map[string]any)["operatorReference"] = ref
			m["candidate"].(map[string]any)["humanK4ApprovalReference"] = ref
		})
		if _, err := ParseProfile(raw); err != nil {
			t.Errorf("ParseProfile rejected reference %q: %v", ref, err)
		}
	}
}
