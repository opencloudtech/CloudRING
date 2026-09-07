// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package roadmapprogram

import (
	"strings"
	"testing"
)

func TestMeasurementInputsRejectIncompleteOrWeakenedTargets(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"missing profile", func(d map[string]any) { d["profiles"] = d["profiles"].([]any)[1:] }, "every management"},
		{"duplicate profile", func(d map[string]any) { p := d["profiles"].([]any); d["profiles"] = append(p, p[0]) }, "duplicate, unknown"},
		{"missing zero-valued RPO", func(d map[string]any) { delete(d["common"].(map[string]any), "singleFailureRPOSeconds") }, "RPO/RTO"},
		{"weak availability", func(d map[string]any) { d["common"].(map[string]any)["availabilityMinimumPercent"] = 99 }, "availability weaken"},
		{"weak upgrade probes", func(d map[string]any) { d["common"].(map[string]any)["probeIntervalMilliseconds"] = 2000 }, "probes or availability"},
		{"missing formula", func(d map[string]any) { delete(d["common"].(map[string]any), "passFormula") }, "formulas"},
		{"weak acknowledgement", func(d map[string]any) {
			d["common"].(map[string]any)["durableAcknowledgementMilliseconds"].(map[string]any)["p99"] = 2000
		}, "acknowledgement"},
		{"missing samples", func(d map[string]any) { delete(d["profiles"].([]any)[0].(map[string]any), "minimumSamples") }, "sample size"},
		{"missing sample unit", func(d map[string]any) { delete(d["profiles"].([]any)[0].(map[string]any), "sampleUnit") }, "sample size"},
		{"missing real lifecycle trials", func(d map[string]any) {
			delete(d["profiles"].([]any)[0].(map[string]any), "minimumLifecycleTrialsPerMethod")
		}, "sample size"},
		{"provider queue cannot absorb healthy latency", func(d map[string]any) {
			d["profiles"].([]any)[1].(map[string]any)["offeredPerSecond"] = 10
			d["profiles"].([]any)[1].(map[string]any)["saturationSearchCeilingPerSecond"] = 40
		}, "queue budget"},
		{"invalid percentile order", func(d map[string]any) {
			d["profiles"].([]any)[0].(map[string]any)["latencyMilliseconds"].(map[string]any)["p50"] = 2000
		}, "latency"},
		{"weak human window", func(d map[string]any) { d["human"].(map[string]any)["representativeDays"] = 1 }, "human measurement"},
		{"weak scale", func(d map[string]any) { d["scale"].(map[string]any)["twoCellCapacityRatioMinimum"] = 1.1 }, "scale thresholds"},
		{"false measured status", func(d map[string]any) { d["status"] = "passed" }, "non-measured status"},
		{"unknown field", func(d map[string]any) { d["common"].(map[string]any)["skipFailures"] = true }, "unknown field"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, repository, document := writeFixture(t)
			defer repository.Close()
			writeFile(t, repository, "roadmap.yaml", document)
			profiles := decodeJSONObject(t, []byte(readShippedRoadmapFile(t, "measurement-profiles.json")))
			test.mutate(profiles)
			writeFile(t, repository, "measurement-profiles.json", string(marshalJSON(t, profiles)))
			err := ValidateDir(root)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid measurement input: got %v, want %q", err, test.want)
			}
		})
	}
}

func TestQualificationDependenciesRemainRequiredAfterIndependentStart(t *testing.T) {
	goals := map[string]*Goal{
		"G22": {ID: "G22", Status: StatusInProgress, DependsOn: []string{"G23"}},
		"G23": {ID: "G23", Status: StatusNotStarted, DependsOn: []string{"G21"}},
		"G24": {ID: "G24", Status: StatusInProgress, DependsOn: []string{"G22", "G23"}},
	}
	if blockers := validateStatuses(goals); len(blockers) != 0 {
		t.Fatalf("independent preparation is not a delivery claim: %v", blockers)
	}
	goals["G24"].Status = StatusDelivered
	blockers := strings.Join(validateStatuses(goals), "\n")
	for _, prerequisite := range []string{"G22", "G23"} {
		if !strings.Contains(blockers, "G24: delivered status requires delivered dependency "+prerequisite) {
			t.Fatalf("missing full qualification barrier %s: %s", prerequisite, blockers)
		}
	}
}
