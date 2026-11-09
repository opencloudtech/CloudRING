// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package rsi

import (
	"errors"
	"math"
	"strconv"
	"testing"
)

func baseVOI() VOIInput { return *validCompliantK3Profile().VOI }

func TestVOIInputBounds(t *testing.T) {
	for name, edit := range map[string]func(*VOIInput){
		"prior zero":        func(v *VOIInput) { v.PriorSuccessProb = "0" },
		"prior one":         func(v *VOIInput) { v.PriorSuccessProb = "1" },
		"test never fires":  func(v *VOIInput) { v.TestSensitivity, v.TestSpecificity = "0", "1" },
		"test always fires": func(v *VOIInput) { v.TestSensitivity, v.TestSpecificity = "1", "0" },
	} {
		in := baseVOI()
		edit(&in)
		if _, err := EvaluateVOI(in); !errors.Is(err, ErrInvalidProfile) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVOIDecisionBoundaries(t *testing.T) {
	// Launching is worth exactly as much as not acting: no reason to launch.
	tie := VOIInput{PriorSuccessProb: "1/2", SuccessNetPayoffEUR: "100", FailureLossEUR: "100", NoActionPayoffEUR: "0",
		TestCostEUR: "0", TestSensitivity: "4/5", TestSpecificity: "3/4", HardLossCapEUR: "1000"}
	if r, err := EvaluateVOI(tie); err != nil || r.NoTestBestAction != "do_not_launch" {
		t.Fatalf("launch EV equal to no action: %+v %v", r, err)
	}
	// With no possible loss the test cannot change the decision: zero net EVSI
	// keeps the no-test action.
	free := VOIInput{PriorSuccessProb: "1/2", SuccessNetPayoffEUR: "100", FailureLossEUR: "0", NoActionPayoffEUR: "0",
		TestCostEUR: "0", TestSensitivity: "4/5", TestSpecificity: "3/4", HardLossCapEUR: "1000"}
	if r, err := EvaluateVOI(free); err != nil || r.NetIncrementalEVEUR != "0" || r.RecommendedAction != "launch_now" {
		t.Fatalf("zero net EVSI: %+v %v", r, err)
	}
	atCap := baseVOI()
	atCap.HardLossCapEUR = atCap.FailureLossEUR
	if r, err := EvaluateVOI(atCap); err != nil || !r.FeasibleUnderLossCap {
		t.Fatalf("loss equal to the cap: %+v %v", r, err)
	}
	if r, err := EvaluateVOI(VOIInput{PriorSuccessProb: "2/5", SuccessNetPayoffEUR: "120000", FailureLossEUR: "60000", NoActionPayoffEUR: "0",
		TestCostEUR: "4000", TestSensitivity: "4/5", TestSpecificity: "3/4", HardLossCapEUR: "80000", CorrelatedLLMRunsCount: 0}); err != nil || !r.ExtremizationRejected {
		t.Fatalf("zero correlated runs: %+v %v", r, err)
	}
}

func TestVOICheckVerdicts(t *testing.T) {
	infeasible := validCompliantK3Profile()
	infeasible.VOI.HardLossCapEUR = "50000"
	rep := evaluate(t, infeasible)
	if rep.VOI.RecommendedAction != "do_not_launch_or_test_until_loss_restructured" || checkStatus(rep, "c20_voi_and_loss_cap") != StatusPass {
		t.Fatalf("restructure recommendation over the cap: action=%s c20=%s", rep.VOI.RecommendedAction, checkStatus(rep, "c20_voi_and_loss_cap"))
	}
	extremized := validCompliantK3Profile()
	extremized.VOI.CorrelatedLLMRunsCount = -1
	if got := checkStatus(evaluate(t, extremized), "c20_voi_and_loss_cap"); got != StatusFail {
		t.Fatalf("extremized correlated runs: c20 %s", got)
	}
}

func basePassK() PassKInput { return *validCompliantK3Profile().PassK }

func TestPassKInputBounds(t *testing.T) {
	bad := map[string]func(*PassKInput){
		"k zero":                  func(in *PassKInput) { in.K = 0 },
		"no tasks":                func(in *PassKInput) { in.Tasks = nil },
		"fewer trials than k":     func(in *PassKInput) { in.Tasks[0] = TaskTrialCount{TaskID: "t", Trials: 3, Successes: 1} },
		"negative successes":      func(in *PassKInput) { in.Tasks[0] = TaskTrialCount{TaskID: "t", Trials: 5, Successes: -1} },
		"successes above trials":  func(in *PassKInput) { in.Tasks[0] = TaskTrialCount{TaskID: "t", Trials: 5, Successes: 6} },
		"no accepted tasks":       func(in *PassKInput) { in.AcceptedTasks, in.AttemptedTasks = 0, 5 },
		"fewer attempted than ok": func(in *PassKInput) { in.AcceptedTasks, in.AttemptedTasks = 5, 3 },
	}
	for name, edit := range bad {
		in := basePassK()
		in.Tasks = append([]TaskTrialCount(nil), in.Tasks...)
		edit(&in)
		if _, err := EvaluatePassK(in); !errors.Is(err, ErrInvalidProfile) {
			t.Errorf("%s: %v", name, err)
		}
	}
	good := basePassK()
	good.Tasks = []TaskTrialCount{{TaskID: "t", Trials: 4, Successes: 2}}
	good.AcceptedTasks, good.AttemptedTasks = 5, 5
	r, err := EvaluatePassK(good)
	if err != nil || r.UnbiasedCombinatorialPassK != "0" || r.UnbiasedCombinatorialPassAt != "1" || r.AcceptanceRate != "1" {
		t.Fatalf("trials equal to k: %+v %v", r, err)
	}
}

func baseExperiment() ExperimentInput { return *validCompliantK3Profile().Experiment }

func TestExperimentInputBounds(t *testing.T) {
	bad := map[string]func(*ExperimentInput){
		"no control units":     func(in *ExperimentInput) { in.ControlAssignedUnits = 0 },
		"no treatment units":   func(in *ExperimentInput) { in.TreatmentAssignedUnits = 0 },
		"one cluster per arm":  func(in *ExperimentInput) { in.ClustersPerArm = 1 },
		"empty clusters":       func(in *ExperimentInput) { in.UnitsPerCluster = 0 },
		"zero standard error":  func(in *ExperimentInput) { in.DiffStandardError = "0" },
		"bad standard error":   func(in *ExperimentInput) { in.DiffStandardError = "x" },
		"zero margin":          func(in *ExperimentInput) { in.NonInferiorityMargin = "0" },
		"bad margin":           func(in *ExperimentInput) { in.NonInferiorityMargin = "x" },
		"negative correlation": func(in *ExperimentInput) { in.IntraclusterCorrelation = "-0.1" },
	}
	for name, edit := range bad {
		in := baseExperiment()
		edit(&in)
		if _, err := EvaluateExperiment(in); !errors.Is(err, ErrInvalidProfile) {
			t.Errorf("%s: %v", name, err)
		}
	}
	minimal := baseExperiment()
	minimal.ControlAssignedUnits, minimal.TreatmentAssignedUnits, minimal.ClustersPerArm, minimal.UnitsPerCluster = 1, 1, 2, 1
	if _, err := EvaluateExperiment(minimal); err != nil {
		t.Fatalf("smallest valid design rejected: %v", err)
	}
}

func TestExperimentDecisionBoundaries(t *testing.T) {
	run := func(edit func(*ExperimentInput)) ExperimentReport {
		t.Helper()
		in := baseExperiment()
		edit(&in)
		r, err := EvaluateExperiment(in)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// chi^2 = d^2/N equals the 10.8276 critical value exactly: d = 54138,
	// N = 270690000. One unit less imbalance stays below it.
	if r := run(func(in *ExperimentInput) { in.ControlAssignedUnits, in.TreatmentAssignedUnits = 135372069, 135317931 }); !r.SRMDetected {
		t.Fatalf("SRM at the critical value not detected: chi2=%s", r.SRMChiSquare)
	}
	if r := run(func(in *ExperimentInput) { in.ControlAssignedUnits, in.TreatmentAssignedUnits = 135372068, 135317932 }); r.SRMDetected {
		t.Fatalf("SRM detected below the critical value: chi2=%s", r.SRMChiSquare)
	}
	// Two clusters per arm leave df = 2, where the two-sided 5% critical t is
	// 4.30: t = 3.845 (p = 0.061) is not significant, t = 4.5 (p = 0.046) is.
	for z, want := range map[string]bool{"3.845": false, "-3.845": false, "4.5": true, "-4.5": true} {
		r := run(func(in *ExperimentInput) { in.ClustersPerArm, in.UnitsPerCluster, in.NaiveZStat = 2, 1, z })
		if r.ClusterSignificantAt005 != want {
			t.Errorf("df=2 t=%s: significant=%t, want %t", z, r.ClusterSignificantAt005, want)
		}
	}
	// The decision is inclusive at the critical value itself: for df = 2 the
	// Cornish-Fisher expansion z + g1/d + g2/d^2 of t(0.975, df).
	z, d := 1.959963984540054, 2.0
	g1 := (z*z*z + z) / 4.0
	g2 := (5*math.Pow(z, 5) + 16*z*z*z + 3*z) / 96.0
	crit := z + g1/d + g2/(d*d)
	if r := run(func(in *ExperimentInput) {
		in.ClustersPerArm, in.UnitsPerCluster, in.NaiveZStat = 2, 1, strconv.FormatFloat(crit, 'g', -1, 64)
	}); !r.ClusterSignificantAt005 {
		t.Errorf("t exactly at the df=2 critical value %v is not significant", crit)
	}
	// DEFF = 1 + (4 - 1) * 1 = 4 halves a naive z of 2.
	if r := run(func(in *ExperimentInput) { in.UnitsPerCluster, in.IntraclusterCorrelation, in.NaiveZStat = 4, "1", "2" }); r.ClusterAdjustedTStat != "1.0000" || r.DesignEffectDEFF != "4.0000" {
		t.Fatalf("cluster-adjusted t: %s deff %s", r.ClusterAdjustedTStat, r.DesignEffectDEFF)
	}
	// One-sided alpha = 0.05 bounds are inclusive at z = 1.6448536.
	if r := run(func(in *ExperimentInput) {
		in.ObservedDiff, in.NonInferiorityMargin, in.DiffStandardError = "0.6448536", "1", "1"
	}); !r.NonInferiorityProvenAt005 {
		t.Fatalf("non-inferiority at the bound: z=%s", r.NonInferiorityZ)
	}
	if r := run(func(in *ExperimentInput) {
		in.ObservedDiff, in.NonInferiorityMargin, in.DiffStandardError = "0", "1.6448536", "1"
	}); !r.TOSTEquivalenceProven005 {
		t.Fatalf("TOST at both bounds: zNI=%s zUpper=%s", r.NonInferiorityZ, r.TOSTUpperZ)
	}
	if r := run(func(in *ExperimentInput) {
		in.ObservedDiff, in.NonInferiorityMargin, in.DiffStandardError = "0.5", "2", "1"
	}); r.TOSTEquivalenceProven005 || !r.NonInferiorityProvenAt005 {
		t.Fatalf("upper bound not met: tost=%t ni=%t", r.TOSTEquivalenceProven005, r.NonInferiorityProvenAt005)
	}
}

func TestExperimentCheckNeedsBalanceAndValidCUPED(t *testing.T) {
	srm := validCompliantK3Profile()
	srm.Experiment.ControlAssignedUnits, srm.Experiment.TreatmentAssignedUnits = 11000, 9000
	cuped := validCompliantK3Profile()
	cuped.Experiment.HasPostTreatmentCovariate = true
	for name, p := range map[string]CandidateProfile{"sample ratio mismatch": srm, "post-treatment covariate": cuped} {
		if got := checkStatus(evaluate(t, p), "c19_experiment_srm_deff_tost"); got != StatusFail {
			t.Errorf("%s: c19 %s", name, got)
		}
	}
}

func TestDiscoveryCountBounds(t *testing.T) {
	base := *validCompliantK3Profile().Discovery
	for _, c := range []struct{ people, accounts int }{{5, -1}, {3, 5}, {-1, -1}} {
		in := base
		in.TotalInterviewedPeople, in.IndependentAccounts = c.people, c.accounts
		if _, err := EvaluateDiscovery(in); !errors.Is(err, ErrInvalidProfile) {
			t.Errorf("people=%d accounts=%d: %v", c.people, c.accounts, err)
		}
	}
	for _, c := range []struct {
		people, accounts int
		inflation        bool
	}{{0, 0, false}, {5, 0, true}, {3, 3, false}, {6, 5, false}, {6, 4, true}} {
		in := base
		in.TotalInterviewedPeople, in.IndependentAccounts = c.people, c.accounts
		r, err := EvaluateDiscovery(in)
		if err != nil || r.AccountInflationDetected != c.inflation {
			t.Errorf("people=%d accounts=%d: inflation=%t err=%v, want %t", c.people, c.accounts, r.AccountInflationDetected, err, c.inflation)
		}
	}
}
