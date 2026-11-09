// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/rsi"
)

func TestRSIEvaluatePropagatesVerdict(t *testing.T) {
	for _, tc := range []struct {
		fixture, verdict, admission, effClass, kill string
		code, failed                                int
	}{
		{"compliant-k3-profile.json", rsi.VerdictPass, rsi.AdmissionDeploy, rsi.ClassK3, rsi.KillSwitchNone, 0, 0},
		{"merge-only-k3-profile.json", rsi.VerdictPass, rsi.AdmissionMerge, rsi.ClassK3, rsi.KillSwitchNone, 0, 0},
		{"tampered-k4-profile.json", rsi.VerdictFail, rsi.AdmissionDeploy, rsi.ClassK4, rsi.KillSwitchL3, 1, 9},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run([]string{"rsi", "evaluate", "--profile", filepath.Join("..", "..", "contracts", "rsi-governance", "fixtures", tc.fixture)}, &out, &errOut)
			if code != tc.code {
				t.Fatalf("code=%d err=%s out=%s", code, &errOut, &out)
			}
			var rep rsi.Report
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
				t.Fatal(err)
			}
			if rep.Verdict != tc.verdict || rep.Admission != tc.admission || rep.Classification.EffectiveClass != tc.effClass ||
				rep.KillSwitchLevel != tc.kill || rep.Failed != tc.failed {
				t.Fatalf("unexpected RSI report: %+v", rep)
			}
		})
	}
}

// A deploy-admission profile without an S1-S6 receipt fails the oracle.
func TestRSIEvaluateDeployRequiresLKGReceipt(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "rsi-governance", "fixtures", "compliant-k3-profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "lkg")
	stripped, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(t.TempDir(), "deploy-without-lkg.json")
	if err := os.WriteFile(profile, stripped, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"rsi", "evaluate", "--profile", profile}, &out, &errOut); code != 1 {
		t.Fatalf("code=%d err=%s out=%s", code, &errOut, &out)
	}
	var rep rsi.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Checks {
		if c.ID == "s1_s6_lkg_promotion" {
			if c.Status != rsi.StatusFail || rep.Failed != 1 || rep.Verdict != rsi.VerdictFail {
				t.Fatalf("deploy without LKG receipt: %+v", rep)
			}
			return
		}
	}
	t.Fatalf("report has no s1_s6_lkg_promotion check: %+v", rep.Checks)
}

// A key that differs from a field name only in case is rejected, so the
// evaluator never reads a profile differently from other JSON readers.
func TestRSIEvaluateRejectsCaseVariantKeys(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "rsi-governance", "fixtures", "merge-only-k3-profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["candidate"].(map[string]any)["DeploymentTargets"] = []any{"hub"}
	variant, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(t.TempDir(), "case-variant.json")
	if err := os.WriteFile(profile, variant, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"rsi", "evaluate", "--profile", profile}, &out, &errOut); code != 2 || out.Len() != 0 {
		t.Fatalf("code=%d err=%s out=%s", code, &errOut, &out)
	}
}

func TestRSIEvaluateRejectsInvalidInvocations(t *testing.T) {
	compliant := filepath.Join("..", "..", "contracts", "rsi-governance", "fixtures", "compliant-k3-profile.json")
	for _, args := range [][]string{
		{"rsi"},
		{"rsi", "--profile", compliant},
		{"rsi", "evaluate"},
		{"rsi", "evaluate", "--profile"},
		{"rsi", "evaluate", "--profile", filepath.Join(t.TempDir(), "missing.json")},
		{"rsi", "evaluate", "--profile", compliant, "extra"},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 2 || out.Len() != 0 || errOut.Len() == 0 {
			t.Fatalf("args=%v code=%d out=%s err=%s", args, code, &out, &errOut)
		}
	}
}

// Only a first argument "rsi" selects the RSI command; anything else, including
// no arguments, keeps the goal verification behaviour.
func TestRunDispatchesOnlyTheRSISubcommand(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		reason string
	}{
		{nil, "invalid_arguments"},
		{[]string{"verify"}, "invalid_arguments"},
		{[]string{"verify", "goal", "--goal", "G01", "--state", "roadmap/state/G00.json", "--output", "json"}, `unsupported_goal_"G01"`},
	} {
		var out, errOut bytes.Buffer
		code := run(tc.args, &out, &errOut)
		want := "cloudring_goal_verification status=BLOCKED reason=" + tc.reason + "\n"
		if code != 2 || out.Len() != 0 || errOut.String() != want {
			t.Fatalf("args=%v code=%d out=%q err=%q", tc.args, code, &out, &errOut)
		}
	}
}

// A profile of exactly the evaluator's size bound is read whole.
func TestRSIEvaluateReadsAProfileAtTheSizeBound(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "rsi-governance", "fixtures", "compliant-k3-profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	open := bytes.IndexByte(raw, '{')
	trimmed := bytes.TrimRight(raw, " \t\r\n")
	if open < 0 || len(trimmed) > maxRSIProfileBytes {
		t.Fatalf("unexpected fixture")
	}
	padded := append(append(append([]byte{}, trimmed[:open+1]...), bytes.Repeat([]byte{' '}, maxRSIProfileBytes-len(trimmed))...), trimmed[open+1:]...)
	if len(padded) != maxRSIProfileBytes || padded[len(padded)-1] != '}' {
		t.Fatalf("padded profile has %d bytes", len(padded))
	}
	profile := filepath.Join(t.TempDir(), "bound.json")
	if err := os.WriteFile(profile, padded, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"rsi", "evaluate", "--profile", profile}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d err=%s", code, &errOut)
	}
}

func TestRSIEvaluateReportsAnUnreadableProfile(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"rsi", "evaluate", "--profile", t.TempDir()}, &out, &errOut); code != 2 || out.Len() != 0 ||
		errOut.String() != "cloudringctl rsi: cannot read profile\n" {
		t.Fatalf("code=%d out=%q err=%q", code, &out, &errOut)
	}
}
