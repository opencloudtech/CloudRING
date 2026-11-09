// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package sliceoracles_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/sliceoracles"
)

// editedBatch returns the canonical batch document with edit applied to the
// oracle sliceID.
func editedBatch(t *testing.T, sliceID string, edit func(map[string]any)) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "slice-oracles", "oracles-32.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range doc["oracles"].([]any) {
		if o := o.(map[string]any); o["sliceId"] == sliceID {
			edit(o)
			found = true
		}
	}
	if !found {
		t.Fatalf("no oracle %s", sliceID)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBatchRejectsIncompleteOrMisorderedOracles(t *testing.T) {
	cases := []struct {
		name, slice, wantErr string
		edit                 func(map[string]any)
	}{
		{"no goals", "C06", "missing goals", func(o map[string]any) { o["goals"] = []any{} }},
		{"no allowed paths", "C06", "missing goals", func(o map[string]any) { o["allowedPaths"] = []any{} }},
		{"no required gates", "C06", "missing goals", func(o map[string]any) { o["requiredGates"] = []any{} }},
		{"C24 waits for C23", "C24", "C24 coreDependencies", func(o map[string]any) { o["coreDependencies"] = []any{"C23"} }},
		{"C20 waits for C19", "C20", "C20 coreDependencies", func(o map[string]any) { o["coreDependencies"] = []any{"C11", "C16", "C19"} }},
		{"unknown dependency", "C12", "unknown dependency", func(o map[string]any) { o["coreDependencies"] = []any{"C99"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sliceoracles.ParseBatch(editedBatch(t, tc.slice, tc.edit))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestReadyQueueSplitDependencies(t *testing.T) {
	batch := loadCanonicalBatch(t)
	ready := func(core, full []string) []string {
		set := func(ids []string) map[string]bool {
			m := make(map[string]bool, len(ids))
			for _, id := range ids {
				m[id] = true
			}
			return m
		}
		return batch.ReadyNoNewHardwareQueue(set(core), set(full))
	}
	// C16 unlocks dependent CORE builds once its own CORE build is accepted.
	got := ready([]string{"C16"}, []string{"C11"})
	for _, want := range []string{"C17:CORE", "C20:CORE", "DBAAS:CORE", "FILESAAS:CORE"} {
		if !slices.Contains(got, want) {
			t.Errorf("C16 CORE + C11 FULL: %s not ready in %v", want, got)
		}
	}
	// Any other dependency must be FULL: a CORE-only C07 does not unlock C15.
	if got := ready([]string{"C07"}, []string{"C11"}); slices.Contains(got, "C15:CORE") || slices.Contains(got, "DNSAAS:CORE") {
		t.Errorf("CORE-only C07 unlocked %v", got)
	}
	// A split slice whose CORE is accepted qualifies once its QUAL dependencies are FULL.
	if got := ready([]string{"C17"}, []string{"C13", "C14"}); !slices.Contains(got, "C17:QUAL") {
		t.Errorf("C17 CORE + C13/C14 FULL: no C17:QUAL in %v", got)
	}
	if got := ready([]string{"C17"}, []string{"C13"}); slices.Contains(got, "C17:QUAL") {
		t.Errorf("C17:QUAL ready without C14 FULL: %v", got)
	}
}

func TestConcurrentWritePRNeedsSliceAndPaths(t *testing.T) {
	batch := loadCanonicalBatch(t)
	for name, active := range map[string][]sliceoracles.ActivePR{
		"no slice id": {{SliceID: " ", TouchedPaths: []string{"pkg/rsi"}}},
		"no paths":    {{SliceID: "SP01"}},
	} {
		err := batch.ValidateConcurrentWritePRs(active)
		if err == nil || !strings.Contains(err.Error(), "must declare sliceId and touchedPaths") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
