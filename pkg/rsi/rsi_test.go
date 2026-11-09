// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package rsi

import (
	"encoding/json"
	"strings"
	"testing"
)

func validCompliantK3Profile() CandidateProfile {
	return CandidateProfile{
		APIVersion: ProfileAPIVersion,
		Kind:       ProfileKind,
		Candidate: CandidateMetadata{
			ID:                    "cand-rsi-001",
			DeclaredClass:         ClassK3,
			ChangedPaths:          []string{"pkg/rsi/rsi.go", "cmd/cloudringctl/commands.go"},
			ReadOnlyOnly:          false,
			ReversibleConfigOnly:  false,
			DeletedOrSkippedTests: 0,
			ModifiedExistingTests: false,
			ModifiedTestdata:      false,
		},
		Gates: GateReceipts{
			G1: G1Receipt{
				EvaluatorFrozenHashVerified: true,
				SuitePassed:                 true,
				NewTestFailedBeforeFix:      true,
				NewTestPassedAfterFix:       true,
				RerunMaskingUsed:            false,
				SilentErrorSwallowing:       0,
				UnseenHoldoutPassed:         true,
				SeededErrorRejected:         true,
			},
			G2: G2Receipt{
				KilledMutants:     18,
				TotalMutants:      20,
				FuzzTargetsPassed: true,
			},
			G3: G3Receipt{
				SASTFindings:                0,
				VulnFindings:                0,
				ExternalCapabilityGate:      true,
				PromptDelimiterOnlySecurity: false,
				ExplanationOnlyApproval:     false,
			},
			G4: G4Receipt{
				ActiveCanaries:              1,
				CanaryStepPercent:           "10",
				CanaryMaxPercent:            "50",
				RequestSuccessRatePercent:   "99.5",
				LatencyP99Ms:                "220",
				CanaryDurationMinutes:       "10",
				CanaryFailuresLast24h:       0,
				TouchesPersistentState:      true,
				DowngradeContinuityVerified: true,
			},
			G5: G5Receipt{
				PortabilityDrillPassed: true,
				DataActVerdict:         VerdictPass,
			},
			G6: G6Receipt{
				AIFailedDeployments:    1,
				AITotalDeployments:     20,
				HumanFailedDeployments: 2,
				HumanTotalDeployments:  20,
			},
			G7: G7Receipt{
				TaskCostUSD:         "1.80",
				MedianTaskCostUSD:   "1.50",
				TaskDurationMinutes: "12",
				ExecutorModelFamily: "family-a",
				OverseerModelFamily: "family-b",
			},
		},
		LKG: &LKGReceipt{
			ImmutableBootloaderVerified:  true,
			PinnedLKGSlots:               2,
			SoakMinutes:                  30,
			WebhookBypassVerified:        true,
			PreMigrationSnapshotVerified: true,
			MetaRSISelfCheckPassed:       true,
			CandidateSHA:                 "a326123af6ca994ce876bb786dff7683f181ca36",
			QuarantinedSHAs:              []string{"deadbeef00000000000000000000000000000000"},
		},
		VOI: &VOIInput{
			PriorSuccessProb:       "2/5",
			SuccessNetPayoffEUR:    "120000",
			FailureLossEUR:         "60000",
			NoActionPayoffEUR:      "0",
			TestCostEUR:            "4000",
			TestSensitivity:        "4/5",
			TestSpecificity:        "3/4",
			HardLossCapEUR:         "80000",
			CorrelatedLLMRunsCount: 3,
		},
		PassK: &PassKInput{
			K: 4,
			Tasks: []TaskTrialCount{
				{TaskID: "t1", Trials: 5, Successes: 5},
				{TaskID: "t2", Trials: 5, Successes: 4},
				{TaskID: "t3", Trials: 5, Successes: 3},
				{TaskID: "t4", Trials: 5, Successes: 0},
			},
			CheapModelCostUSD:  "0.80",
			VerifierCostUSD:    "0.30",
			StrongModelCostUSD: "4.00",
			GateFailRate:       "0.45",
			StrongRetryRate:    "0.10",
			HumanCodingHours:   "40",
			HumanReviewHours:   "28",
			HumanReworkHours:   "12",
			AcceptedTasks:      14,
			AttemptedTasks:     20,
		},
		Experiment: &ExperimentInput{
			ControlAssignedUnits:      10000,
			TreatmentAssignedUnits:    10000,
			ClustersPerArm:            20,
			UnitsPerCluster:           500,
			IntraclusterCorrelation:   "0.05",
			NaiveZStat:                "2.50",
			HasPostTreatmentCovariate: false,
			ObservedDiff:              "0.02",
			DiffStandardError:         "0.01",
			NonInferiorityMargin:      "0.05",
		},
		Discovery: &DiscoveryInput{
			HardConstraintsIntact:        true,
			TotalInterviewedPeople:       12,
			IndependentAccounts:          10,
			HasTechnicalUserEvidence:     true,
			HasEconomicBuyerEvidence:     true,
			HasVetoHolderEvidence:        true,
			UsesMechanicalWTPDivisor:     false,
			UsesRICEToOverrideSecurity:   false,
			ExternalContactOwnerApproved: true,
			HasConsequentialCommitment:   true,
		},
	}
}

func TestEvaluateCompliantK3ProfilePassesAllGates(t *testing.T) {
	prof := validCompliantK3Profile()
	raw, err := json.Marshal(prof)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseProfile(raw)
	if err != nil {
		t.Fatalf("ParseProfile failed: %v", err)
	}
	rep, err := EvaluateCandidate(parsed)
	if err != nil {
		t.Fatalf("EvaluateCandidate failed: %v", err)
	}
	if rep.Verdict != VerdictPass || rep.Failed != 0 || rep.KillSwitchLevel != KillSwitchNone {
		t.Fatalf("expected pass verdict with 0 failed checks, got verdict=%s failed=%d kill=%s checks=%+v",
			rep.Verdict, rep.Failed, rep.KillSwitchLevel, rep.Checks)
	}
	if rep.Classification.EffectiveClass != ClassK3 || !rep.Classification.HoldoutRequired {
		t.Fatalf("expected effective K3 with holdout, got %+v", rep.Classification)
	}
	if rep.VOI == nil || rep.VOI.LaunchNowEVEUR != "12000" || rep.VOI.PositiveTestProb != "47/100" ||
		rep.VOI.PosteriorSuccessGivenPos != "32/47" || rep.VOI.PosteriorSuccessGivenNeg != "8/53" ||
		rep.VOI.GrossPolicyEVEUR != "29400" || rep.VOI.GrossEVSIEUR != "17400" ||
		rep.VOI.NetPolicyEVEUR != "25400" || rep.VOI.NetIncrementalEVEUR != "13400" || rep.VOI.EVPIEUR != "36000" {
		t.Fatalf("unexpected VOI report: %+v", rep.VOI)
	}
	if rep.PassK == nil || rep.PassK.UnbiasedCombinatorialPassK != "3/10" ||
		rep.PassK.UnbiasedCombinatorialPassAt != "3/4" || rep.PassK.FullCascadeCostPerTaskUSD != "3.08" ||
		rep.PassK.NaiveCascadeCostPerTaskUSD != "2.24" || rep.PassK.HumanHoursPerAcceptedTask != "40/7" {
		t.Fatalf("unexpected PassK report: %+v", rep.PassK)
	}
}

func TestClassifyCandidateEscalatesTamperingAndProtectedPathsToK4(t *testing.T) {
	cases := []struct {
		name   string
		meta   CandidateMetadata
		reason string
	}{
		{
			name:   "github-workflow-path",
			meta:   CandidateMetadata{ID: "c1", DeclaredClass: ClassK2, ChangedPaths: []string{".GitHub/workflows/ci.yml"}},
			reason: "protected_k4_path:.github/workflows/ci.yml",
		},
		{
			name:   "path-traversal-evaluator",
			meta:   CandidateMetadata{ID: "c2", DeclaredClass: ClassK2, ChangedPaths: []string{"pkg/../evaluator/score.go"}},
			reason: "path_traversal_or_absolute:pkg/../evaluator/score.go",
		},
		{
			name:   "ops-stop-modification",
			meta:   CandidateMetadata{ID: "c3", DeclaredClass: ClassK1, ChangedPaths: []string{"ops/STOP"}},
			reason: "protected_control_file:ops/stop",
		},
		{
			name:   "deleted-tests",
			meta:   CandidateMetadata{ID: "c4", DeclaredClass: ClassK2, ChangedPaths: []string{"pkg/ocs/spec.go"}, DeletedOrSkippedTests: 1},
			reason: "deleted_or_skipped_tests_requires_k4",
		},
		{
			name:   "co-modified-prod-and-existing-tests",
			meta:   CandidateMetadata{ID: "c5", DeclaredClass: ClassK2, ChangedPaths: []string{"pkg/ocs/spec.go"}, ModifiedExistingTests: true},
			reason: "co_modified_production_and_existing_tests_or_testdata_requires_k4",
		},
		{
			name:   "url-encoded-traversal",
			meta:   CandidateMetadata{ID: "c6", DeclaredClass: ClassK2, ChangedPaths: []string{"pkg/%2e%2e/evaluator/score.go"}},
			reason: "encoded_or_null_path:pkg/%2e%2e/evaluator/score.go",
		},
		{
			name:   "url-encoded-slash-upper",
			meta:   CandidateMetadata{ID: "c7", DeclaredClass: ClassK2, ChangedPaths: []string{"pkg%2Fevaluator/score.go"}},
			reason: "encoded_or_null_path:pkg%2Fevaluator/score.go",
		},
		{
			name:   "url-encoded-backslash",
			meta:   CandidateMetadata{ID: "c8", DeclaredClass: ClassK2, ChangedPaths: []string{"pkg%5Cevaluator/score.go"}},
			reason: "encoded_or_null_path:pkg%5Cevaluator/score.go",
		},
		{
			name:   "null-byte-path",
			meta:   CandidateMetadata{ID: "c9", DeclaredClass: ClassK2, ChangedPaths: []string{"pkg/ocs/spec.go\x00.txt"}},
			reason: "encoded_or_null_path:pkg/ocs/spec.go\x00.txt",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cls, err := ClassifyCandidate(tc.meta)
			if err != nil {
				t.Fatal(err)
			}
			if cls.EffectiveClass != ClassK4 || !cls.HumanApprovalRequired {
				t.Fatalf("expected K4 escalation, got %+v", cls)
			}
			found := false
			for _, r := range cls.EscalationReasons {
				if strings.Contains(r, tc.reason) {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected reason %q in %v", tc.reason, cls.EscalationReasons)
			}
		})
	}
}

func TestExactGateThresholdsAndKillSwitchEscalations(t *testing.T) {
	// Exact 80% (16/20) mutation kill ratio must pass G2; 15/20 (75%) must fail.
	prof := validCompliantK3Profile()
	prof.Gates.G2.KilledMutants = 16
	prof.Gates.G2.TotalMutants = 20
	rep, err := EvaluateCandidate(prof)
	if err != nil || rep.Verdict != VerdictPass {
		t.Fatalf("expected 16/20 (80%%) mutation kill score to pass, got err=%v verdict=%s", err, rep.Verdict)
	}

	prof.Gates.G2.KilledMutants = 15
	rep, err = EvaluateCandidate(prof)
	if err != nil || rep.Verdict != VerdictFail {
		t.Fatalf("expected 15/20 (75%%) mutation kill score to fail, got err=%v verdict=%s", err, rep.Verdict)
	}

	// G6: AI CFR = 3/20 (15%) with human CFR = 3/20 (15%) must pass; 4/20 (20%) must fail and downgrade to K1 + KillSwitchL1.
	prof = validCompliantK3Profile()
	prof.Gates.G6.AIFailedDeployments = 3
	prof.Gates.G6.AITotalDeployments = 20
	prof.Gates.G6.HumanFailedDeployments = 3
	prof.Gates.G6.HumanTotalDeployments = 20
	rep, err = EvaluateCandidate(prof)
	if err != nil || rep.Verdict != VerdictPass || rep.MaxAutonomousClass != ClassK3 {
		t.Fatalf("expected 3/20 CFR boundary to pass, got err=%v verdict=%s maxAuto=%s", err, rep.Verdict, rep.MaxAutonomousClass)
	}

	prof.Gates.G6.AIFailedDeployments = 4
	rep, err = EvaluateCandidate(prof)
	if err != nil || rep.Verdict != VerdictFail || rep.MaxAutonomousClass != ClassK1 || rep.KillSwitchLevel != KillSwitchL1 {
		t.Fatalf("expected 4/20 CFR to trip G6 circuit breaker to K1/L1, got verdict=%s maxAuto=%s kill=%s",
			rep.Verdict, rep.MaxAutonomousClass, rep.KillSwitchLevel)
	}

	// G7: Cost burn > 2x median trips KillSwitchL2.
	prof = validCompliantK3Profile()
	prof.Gates.G7.TaskCostUSD = "3.01"
	prof.Gates.G7.MedianTaskCostUSD = "1.50"
	rep, err = EvaluateCandidate(prof)
	if err != nil || rep.Verdict != VerdictFail || rep.KillSwitchLevel != KillSwitchL2 {
		t.Fatalf("expected >2x median cost burn to trigger L2 kill switch, got verdict=%s kill=%s", rep.Verdict, rep.KillSwitchLevel)
	}

	// Unapproved test tampering trips KillSwitchL3.
	prof = validCompliantK3Profile()
	prof.Candidate.DeletedOrSkippedTests = 2
	rep, err = EvaluateCandidate(prof)
	if err != nil || rep.Verdict != VerdictFail || rep.KillSwitchLevel != KillSwitchL3 {
		t.Fatalf("expected unapproved test deletion to trigger L3 kill switch, got verdict=%s kill=%s", rep.Verdict, rep.KillSwitchLevel)
	}
}

func TestHardLossCapAndExperimentAndDiscoveryTraps(t *testing.T) {
	// C-20: Hard loss cap EUR 20,000 < FailureLossEUR 60,000 blocks launch and sets effective net EVSI to -4000.
	voiIn := validCompliantK3Profile().VOI
	voiIn.HardLossCapEUR = "20000"
	vr, err := EvaluateVOI(*voiIn)
	if err != nil {
		t.Fatal(err)
	}
	if vr.FeasibleUnderLossCap || vr.EffectiveNetEVSIUnderCap != "-4000" || vr.RecommendedAction != "do_not_launch_or_test_until_loss_restructured" {
		t.Fatalf("expected hard loss cap to block launch and test, got %+v", vr)
	}

	// C-19: SRM 10250 vs 9750 (chi^2 = 12.5000), DEFF = 25.9500, N_eff = 385.36, non-inferiority z = 0.0000 (not proven).
	er, err := EvaluateExperiment(ExperimentInput{
		ControlAssignedUnits:      10250,
		TreatmentAssignedUnits:    9750,
		ClustersPerArm:            20,
		UnitsPerCluster:           500,
		IntraclusterCorrelation:   "0.05",
		NaiveZStat:                "2.50",
		HasPostTreatmentCovariate: true,
		ObservedDiff:              "-0.05",
		DiffStandardError:         "0.058949",
		NonInferiorityMargin:      "0.05",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !er.SRMDetected || er.SRMChiSquare != "12.5000" || er.DesignEffectDEFF != "25.9500" ||
		er.EffectiveUnitsPerArm != "385.36" || er.ClusterSignificantAt005 || er.CUPEDValid ||
		er.NonInferiorityProvenAt005 || er.TOSTEquivalenceProven005 || er.Verdict != VerdictFail {
		t.Fatalf("unexpected C-19 experiment diagnostics: %+v", er)
	}

	// C-18: 14 engineers across 3 firms + WTP/1.35 + RICE override rejected.
	dr, err := EvaluateDiscovery(DiscoveryInput{
		HardConstraintsIntact:        false,
		TotalInterviewedPeople:       14,
		IndependentAccounts:          3,
		HasTechnicalUserEvidence:     true,
		HasEconomicBuyerEvidence:     false,
		HasVetoHolderEvidence:        false,
		UsesMechanicalWTPDivisor:     true,
		UsesRICEToOverrideSecurity:   true,
		ExternalContactOwnerApproved: false,
		HasConsequentialCommitment:   false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !dr.AccountInflationDetected || dr.RoleStratificationComplete || dr.MethodologicallyValid || dr.StageGateAuthorized || len(dr.Reasons) != 7 {
		t.Fatalf("expected all 7 C-18 discovery errors flagged, got %+v", dr)
	}
}

func TestOrthogonalSingleGateInvariantsKillMutants(t *testing.T) {
	cases := []struct {
		name           string
		mutate         func(*CandidateProfile)
		wantVerdict    string
		wantKillSwitch string
	}{
		{
			name: "g1_frozen_hash_false",
			mutate: func(p *CandidateProfile) {
				p.Gates.G1.EvaluatorFrozenHashVerified = false
			},
			wantVerdict: VerdictFail,
		},
		{
			name: "g1_seeded_error_false",
			mutate: func(p *CandidateProfile) {
				p.Gates.G1.SeededErrorRejected = false
			},
			wantVerdict: VerdictFail,
		},
		{
			name: "g1_unseen_holdout_false",
			mutate: func(p *CandidateProfile) {
				p.Gates.G1.UnseenHoldoutPassed = false
			},
			wantVerdict: VerdictFail,
		},
		{
			name: "g1_suite_passed_false",
			mutate: func(p *CandidateProfile) {
				p.Gates.G1.SuitePassed = false
			},
			wantVerdict: VerdictFail,
		},
		{
			name: "g1_rerun_masking_true",
			mutate: func(p *CandidateProfile) {
				p.Gates.G1.RerunMaskingUsed = true
			},
			wantVerdict: VerdictFail,
		},
		{
			name: "g1_silent_error_swallowing_nonzero",
			mutate: func(p *CandidateProfile) {
				p.Gates.G1.SilentErrorSwallowing = 1
			},
			wantVerdict: VerdictFail,
		},
		{
			name: "g2_fuzz_targets_false",
			mutate: func(p *CandidateProfile) {
				p.Gates.G2.FuzzTargetsPassed = false
			},
			wantVerdict: VerdictFail,
		},
		{
			name: "g3_external_cap_false",
			mutate: func(p *CandidateProfile) {
				p.Gates.G3.ExternalCapabilityGate = false
			},
			wantVerdict: VerdictFail,
		},
		{
			name: "g3_prompt_delimiter_only_true",
			mutate: func(p *CandidateProfile) {
				p.Gates.G3.PromptDelimiterOnlySecurity = true
			},
			wantVerdict: VerdictFail,
		},
		{
			name: "g3_explanation_only_approval_true",
			mutate: func(p *CandidateProfile) {
				p.Gates.G3.ExplanationOnlyApproval = true
			},
			wantVerdict: VerdictFail,
		},
		{
			name: "g4_stateful_downgrade_false",
			mutate: func(p *CandidateProfile) {
				p.Gates.G4.TouchesPersistentState = true
				p.Gates.G4.DowngradeContinuityVerified = false
			},
			wantVerdict: VerdictFail,
		},
		{
			name: "g5_data_act_fail",
			mutate: func(p *CandidateProfile) {
				p.Gates.G5.DataActVerdict = "fail"
			},
			wantVerdict: VerdictFail,
		},
		{
			name: "g5_portability_drill_false",
			mutate: func(p *CandidateProfile) {
				p.Gates.G5.PortabilityDrillPassed = false
			},
			wantVerdict: VerdictFail,
		},
		{
			name: "g6_ai_cfr_4_of_20_with_zero_human",
			mutate: func(p *CandidateProfile) {
				p.Gates.G6.AIFailedDeployments = 4
				p.Gates.G6.AITotalDeployments = 20
				p.Gates.G6.HumanFailedDeployments = 0
				p.Gates.G6.HumanTotalDeployments = 0
			},
			wantVerdict: VerdictFail,
		},
		{
			name: "g7_exact_2x_burn_boundary_passes",
			mutate: func(p *CandidateProfile) {
				p.Gates.G7.TaskCostUSD = "3.00"
				p.Gates.G7.MedianTaskCostUSD = "1.50"
			},
			wantVerdict:    VerdictPass,
			wantKillSwitch: KillSwitchNone,
		},
		{
			name: "g7_same_family_overseer_fails",
			mutate: func(p *CandidateProfile) {
				p.Gates.G7.ExecutorModelFamily = "family-a"
				p.Gates.G7.OverseerModelFamily = "family-a"
			},
			wantVerdict: VerdictFail,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prof := validCompliantK3Profile()
			tc.mutate(&prof)
			rep, err := EvaluateCandidate(prof)
			if err != nil {
				t.Fatalf("EvaluateCandidate returned unexpected error: %v", err)
			}
			if rep.Verdict != tc.wantVerdict {
				t.Fatalf("expected verdict %q, got %q (checks=%+v)", tc.wantVerdict, rep.Verdict, rep.Checks)
			}
			if tc.wantKillSwitch != "" && rep.KillSwitchLevel != tc.wantKillSwitch {
				t.Fatalf("expected killSwitchLevel %q, got %q", tc.wantKillSwitch, rep.KillSwitchLevel)
			}
		})
	}
}

func TestOrthogonalDiscoveryAndDecisionScienceInvariants(t *testing.T) {
	baseDiscovery := func() DiscoveryInput {
		return DiscoveryInput{
			HardConstraintsIntact:        true,
			TotalInterviewedPeople:       12,
			IndependentAccounts:          10,
			HasTechnicalUserEvidence:     true,
			HasEconomicBuyerEvidence:     true,
			HasVetoHolderEvidence:        true,
			UsesMechanicalWTPDivisor:     false,
			UsesRICEToOverrideSecurity:   false,
			ExternalContactOwnerApproved: true,
			HasConsequentialCommitment:   true,
		}
	}

	validRep, err := EvaluateDiscovery(baseDiscovery())
	if err != nil {
		t.Fatalf("expected valid baseline discovery input, got err=%v", err)
	}
	if !validRep.MethodologicallyValid || !validRep.StageGateAuthorized || !validRep.RoleStratificationComplete || validRep.AccountInflationDetected || len(validRep.Reasons) != 0 {
		t.Fatalf("expected valid baseline discovery report, got %+v", validRep)
	}

	flips := []struct {
		name           string
		mutate         func(*DiscoveryInput)
		expectedReason string
	}{
		{
			name:           "hard-constraints-violated",
			mutate:         func(in *DiscoveryInput) { in.HardConstraintsIntact = false },
			expectedReason: "hard_architectural_or_security_constraints_violated",
		},
		{
			name: "account-inflation-14-in-3",
			mutate: func(in *DiscoveryInput) {
				in.TotalInterviewedPeople = 14
				in.IndependentAccounts = 3
			},
			expectedReason: "multiple_interviewees_in_same_firm_counted_as_independent_accounts",
		},
		{
			name:           "missing-technical-user-evidence",
			mutate:         func(in *DiscoveryInput) { in.HasTechnicalUserEvidence = false },
			expectedReason: "missing_stratified_evidence_across_user_buyer_and_veto_holder",
		},
		{
			name:           "missing-economic-buyer-evidence",
			mutate:         func(in *DiscoveryInput) { in.HasEconomicBuyerEvidence = false },
			expectedReason: "missing_stratified_evidence_across_user_buyer_and_veto_holder",
		},
		{
			name:           "missing-veto-holder-evidence",
			mutate:         func(in *DiscoveryInput) { in.HasVetoHolderEvidence = false },
			expectedReason: "missing_stratified_evidence_across_user_buyer_and_veto_holder",
		},
		{
			name:           "uses-mechanical-wtp-divisor",
			mutate:         func(in *DiscoveryInput) { in.UsesMechanicalWTPDivisor = true },
			expectedReason: "mechanical_hypothetical_wtp_divisor_is_invalid",
		},
		{
			name:           "uses-rice-to-override-security",
			mutate:         func(in *DiscoveryInput) { in.UsesRICEToOverrideSecurity = true },
			expectedReason: "rice_score_cannot_override_security_or_isolation",
		},
		{
			name:           "external-contact-unapproved",
			mutate:         func(in *DiscoveryInput) { in.ExternalContactOwnerApproved = false },
			expectedReason: "external_contact_requires_explicit_owner_approval",
		},
		{
			name:           "missing-consequential-commitment",
			mutate:         func(in *DiscoveryInput) { in.HasConsequentialCommitment = false },
			expectedReason: "praise_without_consequential_migration_or_pilot_commitment",
		},
	}

	for _, tc := range flips {
		t.Run(tc.name, func(t *testing.T) {
			in := baseDiscovery()
			tc.mutate(&in)
			dr, err := EvaluateDiscovery(in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dr.MethodologicallyValid || dr.StageGateAuthorized {
				t.Fatalf("expected single flip %s to invalidate discovery and block stage gate, got %+v", tc.name, dr)
			}
			if len(dr.Reasons) != 1 || dr.Reasons[0] != tc.expectedReason {
				t.Fatalf("expected exact single reason %q, got %v", tc.expectedReason, dr.Reasons)
			}
		})
	}

	voiIn := *validCompliantK3Profile().VOI
	voiIn.TestCostEUR = "40000"
	vr, err := EvaluateVOI(voiIn)
	if err != nil {
		t.Fatalf("EvaluateVOI failed: %v", err)
	}
	if vr.EVPIEUR != "36000" || vr.GrossEVSIEUR != "17400" || vr.NetIncrementalEVEUR != "-22600" ||
		vr.NetPolicyEVEUR != "-10600" || vr.RecommendedAction != "launch_now" {
		t.Fatalf("expected overpriced test to preserve launch_now with negative net EVSI, got %+v", vr)
	}

	baseExp := *validCompliantK3Profile().Experiment
	baseExp.ObservedDiff = "0.00"
	baseExp.DiffStandardError = "0.01"
	baseExp.NonInferiorityMargin = "0.05"
	baseExp.NaiveZStat = "15.0"
	cleanExp, err := EvaluateExperiment(baseExp)
	if err != nil {
		t.Fatalf("EvaluateExperiment clean failed: %v", err)
	}
	if cleanExp.SRMDetected || !cleanExp.CUPEDValid || !cleanExp.ClusterSignificantAt005 ||
		!cleanExp.NonInferiorityProvenAt005 || !cleanExp.TOSTEquivalenceProven005 || cleanExp.Verdict != VerdictPass {
		t.Fatalf("expected clean experiment to prove cluster sig, NI, and TOST equivalence, got %+v", cleanExp)
	}

	srmOnly := baseExp
	srmOnly.ControlAssignedUnits = 10250
	srmOnly.TreatmentAssignedUnits = 9750
	srmRep, err := EvaluateExperiment(srmOnly)
	if err != nil {
		t.Fatalf("EvaluateExperiment srmOnly failed: %v", err)
	}
	if !srmRep.SRMDetected || !srmRep.CUPEDValid || srmRep.ClusterSignificantAt005 ||
		srmRep.NonInferiorityProvenAt005 || srmRep.TOSTEquivalenceProven005 || srmRep.Verdict != VerdictFail {
		t.Fatalf("expected isolated SRM to invalidate experiment while keeping CUPEDValid=true, got %+v", srmRep)
	}

	cupedOnly := baseExp
	cupedOnly.HasPostTreatmentCovariate = true
	cupedRep, err := EvaluateExperiment(cupedOnly)
	if err != nil {
		t.Fatalf("EvaluateExperiment cupedOnly failed: %v", err)
	}
	if cupedRep.SRMDetected || cupedRep.CUPEDValid || cupedRep.ClusterSignificantAt005 ||
		!cupedRep.NonInferiorityProvenAt005 || !cupedRep.TOSTEquivalenceProven005 || cupedRep.Verdict != VerdictFail {
		t.Fatalf("expected isolated post-treatment covariate to set CUPEDValid=false and Verdict=fail while SRMDetected=false, got %+v", cupedRep)
	}

	pkRep, err := EvaluatePassK(PassKInput{
		K: 3,
		Tasks: []TaskTrialCount{
			{TaskID: "t1", Trials: 6, Successes: 5},
			{TaskID: "t2", Trials: 5, Successes: 3},
			{TaskID: "t3", Trials: 4, Successes: 2},
		},
		CheapModelCostUSD:  "0.50",
		VerifierCostUSD:    "0.20",
		StrongModelCostUSD: "3.00",
		GateFailRate:       "1/2",
		StrongRetryRate:    "1/5",
		HumanCodingHours:   "10",
		HumanReviewHours:   "5",
		HumanReworkHours:   "3",
		AcceptedTasks:      9,
		AttemptedTasks:     12,
	})
	if err != nil {
		t.Fatalf("EvaluatePassK heterogeneous failed: %v", err)
	}
	if pkRep.MeanPass1 != "29/45" || pkRep.UnbiasedCombinatorialPassK != "1/5" || pkRep.UnbiasedCombinatorialPassAt != "1" ||
		pkRep.HumanHoursPerAcceptedTask != "2" || pkRep.AcceptanceRate != "3/4" {
		t.Fatalf("unexpected heterogeneous PassK report: %+v", pkRep)
	}
}
