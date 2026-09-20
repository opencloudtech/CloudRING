package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyCurrentG00RemainsBlocked(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(workingDirectory, "../.."))
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(workingDirectory)
	report, err := verify("G00", "roadmap/state/G00.json")
	if err != nil {
		t.Fatal(err)
	}
	if report["verdict"] != "blocked" || report["exactTupleBound"] != false {
		t.Fatalf("unexpected G00 report: %#v", report)
	}
	blockers, ok := report["blockers"].([]string)
	if !ok || len(blockers) == 0 {
		t.Fatalf("blocked report lost blockers: %#v", report)
	}
}

func TestVerifyRejectsUnsupportedGoalAndStatePath(t *testing.T) {
	if _, err := verify("G01", "roadmap/state/G00.json"); err == nil {
		t.Fatal("unsupported goal was accepted")
	}
	if _, err := verify("G00", "roadmap/state/G01.json"); err == nil {
		t.Fatal("wrong state path was accepted")
	}
}
