// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/opencloudtech/CloudRING/internal/roadmapprogram"
)

type repoProof struct {
	Main   *string
	Checks string
	Pin    *string
}
type state struct {
	Goal         string
	Status       string
	Repositories struct {
		Public    repoProof
		Reference repoProof
		Provider  repoProof
	}
	Artifacts        []json.RawMessage
	Deployments      []struct{ Target string }
	Blockers         []string
	ReleaseManifest  json.RawMessage
	RollbackBoundary *string
	Verdict          string
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errOut io.Writer) int {
	if len(args) < 2 || args[0] != "verify" || args[1] != "goal" {
		return blocked(errOut, "invalid arguments")
	}
	f := flag.NewFlagSet("cloudringctl verify goal", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	goal := f.String("goal", "", "goal")
	statePath := f.String("state", "", "state")
	output := f.String("output", "", "output")
	if err := f.Parse(args[2:]); err != nil || f.NArg() != 0 || *goal == "" || *statePath == "" || *output != "json" {
		return blocked(errOut, "goal, state and output=json are required")
	}
	report, err := verify(*goal, *statePath)
	if err != nil {
		return blocked(errOut, err.Error())
	}
	if err := json.NewEncoder(out).Encode(report); err != nil {
		return 1
	}
	if report["verdict"] != "pass" {
		return 2
	}
	return 0
}

func blocked(w io.Writer, reason string) int {
	_, _ = fmt.Fprintf(w, "cloudring_goal_verification status=BLOCKED reason=%s\n", strings.ReplaceAll(reason, " ", "_"))
	return 2
}

func verify(goalID, statePath string) (map[string]any, error) {
	if goalID != "G00" {
		return nil, fmt.Errorf("unsupported goal %q", goalID)
	}
	path := filepath.ToSlash(filepath.Clean(statePath))
	if filepath.IsAbs(statePath) || path != "roadmap/state/G00.json" {
		return nil, fmt.Errorf("state must be exactly roadmap/state/G00.json")
	}
	if err := roadmapprogram.ValidateDir("roadmap"); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path is fail-closed to the repository-local G00 state file above.
	if err != nil {
		return nil, err
	}
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if s.Goal != "G00" {
		return nil, fmt.Errorf("state goal must be G00")
	}
	blockers := append([]string(nil), s.Blockers...)
	if s.Status != "delivered" {
		blockers = append(blockers, "G00 state is not delivered")
	}
	if s.Verdict != "pass" {
		blockers = append(blockers, "G00 state verdict is not pass")
	}
	publicSHA := ""
	if s.Repositories.Public.Main == nil {
		blockers = append(blockers, "public accepted SHA is missing")
	} else {
		publicSHA = *s.Repositories.Public.Main
	}
	if s.Repositories.Public.Checks != "green" {
		blockers = append(blockers, "public checks are not green")
	}
	for name, p := range map[string]repoProof{"reference": s.Repositories.Reference, "provider": s.Repositories.Provider} {
		if p.Main == nil || p.Pin == nil || (publicSHA != "" && *p.Pin != publicSHA) {
			blockers = append(blockers, name+" exact public pin is missing or mismatched")
		}
		if p.Checks != "green" {
			blockers = append(blockers, name+" checks are not green")
		}
	}
	if len(s.Artifacts) == 0 {
		blockers = append(blockers, "sanitized baseline artifacts are missing")
	}
	targets := map[string]bool{}
	for _, d := range s.Deployments {
		targets[d.Target] = true
	}
	if !targets["public_clean_room"] || !targets["hub"] {
		blockers = append(blockers, "public clean-room and hub deployments are missing")
	}
	sort.Strings(blockers)
	blockers = unique(blockers)
	verified := len(blockers) == 0 && s.Status == "delivered" && s.Verdict == "pass" && len(s.ReleaseManifest) > 0 && string(s.ReleaseManifest) != "null" && s.RollbackBoundary != nil
	status, verdict := "blocked", "blocked"
	if verified {
		status, verdict = "verified", "pass"
	}
	return map[string]any{
		"schemaVersion": "cloudring.goal-verification/v1",
		"goal":          "G00", "requirement": "CR-G00-DELIVERY", "state": s.Status, "verdict": verdict,
		"exactTupleBound": verified, "truthfulBaseline": status, "sourceBoundary": status,
		"protectedDelivery": status, "hubBaseline": status, "blockers": blockers,
		"nonClaims": []string{"blocked evidence is not readiness", "this verifier performs no live mutation", "this verifier does not prove production readiness"},
	}, nil
}

func unique(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
