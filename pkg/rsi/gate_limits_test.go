// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package rsi

import (
	"strings"
	"testing"
)

func TestTouchesDeploySurface(t *testing.T) {
	cases := map[string]bool{
		"pkg/rsi/rsi.go":             false,
		"docs/deploy.md":             false,
		"pkg/deployer/x.go":          false,
		"cmd/cloudring_core_tool/x":  false,
		"deploy/kubernetes/x.yaml":   true,
		"a/IAC/b.tf":                 true,
		"cloudring_core":             true,
		".gitmodules":                true,
		".github/workflows":          true,
		".github/workflows/ci.yml":   true,
		".github/workflows-note.md":  false,
		"":                           true,
		"   ":                        true,
		".":                          true,
		"/abs/x.go":                  true,
		"pkg/../x.go":                true,
		"pkg/x%41.go":                true,
		`pkg\x.go`:                   true,
		"pkg/x\x00.go":               true,
		" deploy/x.yaml ":            true,
		"reference/x/Deploy/k8s.yml": true,
	}
	for raw, want := range cases {
		if got := touchesDeploySurface(raw); got != want {
			t.Errorf("touchesDeploySurface(%q) = %t, want %t", raw, got, want)
		}
	}
}

func TestG4CanaryLimits(t *testing.T) {
	cases := []struct {
		name string
		edit func(*G4Receipt)
		pass bool
	}{
		{"compliant", func(*G4Receipt) {}, true},
		{"two active canaries", func(g *G4Receipt) { g.ActiveCanaries = 2 }, false},
		{"step above 10%", func(g *G4Receipt) { g.CanaryStepPercent = "10.1" }, false},
		{"max weight at 50%", func(g *G4Receipt) { g.CanaryMaxPercent = "50" }, true},
		{"max weight above 50%", func(g *G4Receipt) { g.CanaryMaxPercent = "50.1" }, false},
		{"success at 99%", func(g *G4Receipt) { g.RequestSuccessRatePercent = "99" }, true},
		{"success below 99%", func(g *G4Receipt) { g.RequestSuccessRatePercent = "98.9" }, false},
		{"p99 at 500 ms", func(g *G4Receipt) { g.LatencyP99Ms = "500" }, true},
		{"p99 above 500 ms", func(g *G4Receipt) { g.LatencyP99Ms = "500.1" }, false},
		{"burn at 10% of budget", func(g *G4Receipt) { g.CanaryDurationMinutes = "43.2" }, true},
		{"burn above 10% of budget", func(g *G4Receipt) { g.CanaryDurationMinutes = "43.3" }, false},
		{"two failures in 24h", func(g *G4Receipt) { g.CanaryFailuresLast24h = 2 }, true},
		{"three failures in 24h", func(g *G4Receipt) { g.CanaryFailuresLast24h = 3 }, false},
		{"stateful without downgrade proof", func(g *G4Receipt) { g.DowngradeContinuityVerified = false }, false},
		{"stateless without downgrade proof", func(g *G4Receipt) {
			g.TouchesPersistentState, g.DowngradeContinuityVerified = false, false
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validCompliantK3Profile()
			p.Gates.G4.CanaryStepPercent = "10"
			tc.edit(&p.Gates.G4)
			rep := evaluate(t, p)
			want := StatusFail
			if tc.pass {
				want = StatusPass
			}
			if got := checkStatus(rep, "g4_canary_slo_and_stateful_downgrade"); got != want {
				t.Fatalf("g4 status %s, want %s: %+v", got, want, checkOf(rep, "g4_canary_slo_and_stateful_downgrade"))
			}
			wantKill := KillSwitchNone
			if p.Gates.G4.CanaryFailuresLast24h >= 3 {
				wantKill = KillSwitchL1
			}
			if rep.KillSwitchLevel != wantKill {
				t.Fatalf("kill switch %s, want %s", rep.KillSwitchLevel, wantKill)
			}
		})
	}
}

func TestG6RejectsInvalidCounts(t *testing.T) {
	cases := map[string]G6Receipt{
		"negative AI failures":        {AIFailedDeployments: -1, AITotalDeployments: 20, HumanFailedDeployments: 2, HumanTotalDeployments: 20},
		"negative AI total":           {AIFailedDeployments: 0, AITotalDeployments: -1, HumanFailedDeployments: 2, HumanTotalDeployments: 20},
		"AI failures above total":     {AIFailedDeployments: 3, AITotalDeployments: 2, HumanFailedDeployments: 2, HumanTotalDeployments: 2},
		"negative human failures":     {AIFailedDeployments: 1, AITotalDeployments: 20, HumanFailedDeployments: -1, HumanTotalDeployments: 20},
		"negative human total":        {AIFailedDeployments: 1, AITotalDeployments: 20, HumanFailedDeployments: 0, HumanTotalDeployments: -1},
		"human failures above total":  {AIFailedDeployments: 1, AITotalDeployments: 20, HumanFailedDeployments: 3, HumanTotalDeployments: 2},
		"cold start with bad history": {AIFailedDeployments: 0, AITotalDeployments: 0, HumanFailedDeployments: 3, HumanTotalDeployments: 2},
	}
	for name, g6 := range cases {
		t.Run(name, func(t *testing.T) {
			p := validCompliantK3Profile()
			p.Gates.G6 = g6
			rep := evaluate(t, p)
			if checkStatus(rep, "g6_dora_cfr_circuit_breaker") != StatusFail || rep.AIChangeFailRate != "0" ||
				rep.MaxAutonomousClass != ClassK1 || rep.KillSwitchLevel != KillSwitchL1 {
				t.Fatalf("invalid G6 counts were accepted: aiCFR=%s maxAuto=%s kill=%s check=%+v",
					rep.AIChangeFailRate, rep.MaxAutonomousClass, rep.KillSwitchLevel, checkOf(rep, "g6_dora_cfr_circuit_breaker"))
			}
		})
	}
}

func TestG7BudgetLimits(t *testing.T) {
	cases := []struct {
		name                   string
		cost, median, duration string
		pass                   bool
		kill                   string
	}{
		{"compliant", "1.80", "1.50", "12", true, KillSwitchNone},
		{"cost at cap", "10", "6", "12", true, KillSwitchNone},
		{"cost above cap", "11", "6", "12", false, KillSwitchNone},
		{"duration at cap", "1.80", "1.50", "30", true, KillSwitchNone},
		{"duration above cap", "1.80", "1.50", "30.1", false, KillSwitchNone},
		{"cost at twice median", "3", "1.50", "12", true, KillSwitchNone},
		{"cost above twice median", "3.01", "1.50", "12", false, KillSwitchL2},
		{"zero median", "0", "0", "12", false, KillSwitchL2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validCompliantK3Profile()
			p.Gates.G7.TaskCostUSD, p.Gates.G7.MedianTaskCostUSD, p.Gates.G7.TaskDurationMinutes = tc.cost, tc.median, tc.duration
			rep := evaluate(t, p)
			want := StatusFail
			if tc.pass {
				want = StatusPass
			}
			if got := checkStatus(rep, "g7_budget_and_cross_family_overseer"); got != want || rep.KillSwitchLevel != tc.kill {
				t.Fatalf("g7 status %s (want %s) kill %s (want %s): %+v", got, want, rep.KillSwitchLevel, tc.kill, checkOf(rep, "g7_budget_and_cross_family_overseer"))
			}
		})
	}
	for _, fam := range [][2]string{{"", "family-b"}, {"family-a", ""}, {"family-a", " FAMILY-A "}} {
		p := validCompliantK3Profile()
		p.Gates.G7.ExecutorModelFamily, p.Gates.G7.OverseerModelFamily = fam[0], fam[1]
		if got := checkStatus(evaluate(t, p), "g7_budget_and_cross_family_overseer"); got != StatusFail {
			t.Errorf("executor %q overseer %q: g7 %s, want %s", fam[0], fam[1], got, StatusFail)
		}
	}
}

func TestLKGCheckSummary(t *testing.T) {
	rep := evaluate(t, validCompliantK3Profile())
	if c := checkOf(rep, "s1_s6_lkg_promotion"); c.Status != StatusPass || !strings.HasPrefix(c.Summary, "S1-S6 hold: pinnedSlots=2 soak=30min") {
		t.Fatalf("valid LKG receipt: %+v", c)
	}
	p := validCompliantK3Profile()
	p.LKG.SoakMinutes = MinSoakMinutes - 1
	if c := checkOf(evaluate(t, p), "s1_s6_lkg_promotion"); c.Status != StatusFail || !strings.HasPrefix(c.Summary, "S2: ") {
		t.Fatalf("short soak: %+v", c)
	}
}
