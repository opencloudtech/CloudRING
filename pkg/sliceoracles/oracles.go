// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Package sliceoracles implements CloudRING's Fork 1A (32-oracle batch
// autonomous acceptance), Fork 2A (CORE vs QUAL dependency split and 2-PR
// non-overlapping path concurrency), and Deferred Fork 3 (no-new-hardware
// subgraph execution under two-slot LKG safety S1-S6 and RSI gates G1-G7).
package sliceoracles

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/opencloudtech/CloudRING/pkg/rsi"
)

const (
	ExpectedAPIVersion = "cloudring.org/slice-oracles/v1"
	ExpectedKind       = "SliceOracleBatch"
	ExpectedSliceCount = 32
	MaxWritePRsPerRepo = 2
	MinPinnedLKGSlots  = 2
	MinSoakMinutes     = 30
)

// Batch represents the frozen 32-oracle contract (Fork 1A + Fork 2A + Deferred Fork 3).
type Batch struct {
	APIVersion                   string        `json:"apiVersion"`
	Kind                         string        `json:"kind"`
	DecisionForks                DecisionForks `json:"decisionForks"`
	MaxConcurrentWritePRsPerRepo int           `json:"maxConcurrentWritePRsPerRepo"`
	OwnerAcceptanceLatencyDays   int           `json:"ownerAcceptanceLatencyDays"`
	WeeklyOwnerAuditHours        int           `json:"weeklyOwnerAuditHours"`
	LKGInvariants                []string      `json:"lkgInvariants"`
	Oracles                      []SliceOracle `json:"oracles"`
}

// DecisionForks records the locked ROUTE-v2 §7 fork choices.
type DecisionForks struct {
	Fork1 string `json:"fork1"`
	Fork2 string `json:"fork2"`
	Fork3 string `json:"fork3"`
}

// SliceOracle defines the machine-verifiable acceptance oracle for one delivery slice.
type SliceOracle struct {
	SliceID               string   `json:"sliceId"`
	Title                 string   `json:"title"`
	Goals                 []string `json:"goals"`
	SplitMode             bool     `json:"splitMode"`
	CoreDependencies      []string `json:"coreDependencies"`
	QualDependencies      []string `json:"qualDependencies"`
	RequiresFork3Hardware bool     `json:"requiresFork3Hardware"`
	AllowedPaths          []string `json:"allowedPaths"`
	AutonomyClass         string   `json:"autonomyClass"`
	VerificationCommand   string   `json:"verificationCommand"`
	RequiredGates         []string `json:"requiredGates"`
	DaysHist              string   `json:"daysHist"`
	DaysFactory           string   `json:"daysFactory"`
}

// LKGSafetyState captures the 6 necessary and sufficient self-evolution liveness invariants (S1-S6).
type LKGSafetyState struct {
	ImmutableBootloaderVerified  bool     `json:"immutableBootloaderVerified"`
	PinnedLKGSlots               int      `json:"pinnedLkgSlots"`
	SoakMinutes                  int      `json:"soakMinutes"`
	WebhookBypassVerified        bool     `json:"webhookBypassVerified"`
	PreMigrationSnapshotVerified bool     `json:"preMigrationSnapshotVerified"`
	MetaRSISelfCheckPassed       bool     `json:"metaRsiSelfCheckPassed"`
	CandidateSHA                 string   `json:"candidateSha"`
	QuarantinedSHAs              []string `json:"quarantinedShas"`
}

// ActivePR describes an open write PR for Fork 2A concurrency validation.
type ActivePR struct {
	SliceID      string   `json:"sliceId"`
	TouchedPaths []string `json:"touchedPaths"`
}

// SliceAcceptanceReceipt returns the deterministic verdict for a slice candidate.
type SliceAcceptanceReceipt struct {
	SliceID       string      `json:"sliceId"`
	Phase         string      `json:"phase"`
	Verdict       string      `json:"verdict"`
	PromotedToLKG bool        `json:"promotedToLkg"`
	Blockers      []string    `json:"blockers,omitempty"`
	RSIReport     *rsi.Report `json:"rsiReport,omitempty"`
}

// ParseBatch strictly decodes and validates the 32-oracle batch contract.
func ParseBatch(data []byte) (*Batch, error) {
	if len(data) == 0 {
		return nil, errors.New("sliceoracles: empty oracle batch")
	}
	var b Batch
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("sliceoracles: decode batch: %w", err)
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

// Validate checks structural, Fork 1A/2A/3, and DAG acyclicity invariants.
func (b *Batch) Validate() error {
	if b == nil {
		return errors.New("sliceoracles: nil batch")
	}
	if b.APIVersion != ExpectedAPIVersion {
		return fmt.Errorf("sliceoracles: invalid apiVersion %q", b.APIVersion)
	}
	if b.Kind != ExpectedKind {
		return fmt.Errorf("sliceoracles: invalid kind %q", b.Kind)
	}
	if b.MaxConcurrentWritePRsPerRepo != MaxWritePRsPerRepo {
		return fmt.Errorf("sliceoracles: maxConcurrentWritePRsPerRepo must be %d, got %d", MaxWritePRsPerRepo, b.MaxConcurrentWritePRsPerRepo)
	}
	if b.OwnerAcceptanceLatencyDays != 0 {
		return fmt.Errorf("sliceoracles: Fork 1A requires ownerAcceptanceLatencyDays=0, got %d", b.OwnerAcceptanceLatencyDays)
	}
	if len(b.LKGInvariants) != 6 {
		return fmt.Errorf("sliceoracles: expected 6 S1-S6 LKG invariants, got %d", len(b.LKGInvariants))
	}
	if len(b.Oracles) != ExpectedSliceCount {
		return fmt.Errorf("sliceoracles: expected %d slice oracles, got %d", ExpectedSliceCount, len(b.Oracles))
	}

	byID := make(map[string]SliceOracle, len(b.Oracles))
	for _, o := range b.Oracles {
		if strings.TrimSpace(o.SliceID) == "" {
			return errors.New("sliceoracles: empty sliceId")
		}
		if _, exists := byID[o.SliceID]; exists {
			return fmt.Errorf("sliceoracles: duplicate sliceId %q", o.SliceID)
		}
		if len(o.Goals) == 0 || len(o.AllowedPaths) == 0 || len(o.RequiredGates) == 0 {
			return fmt.Errorf("sliceoracles: slice %s missing goals, allowedPaths, or requiredGates", o.SliceID)
		}
		if o.SplitMode && len(o.QualDependencies) == 0 {
			return fmt.Errorf("sliceoracles: split slice %s must declare qualDependencies", o.SliceID)
		}
		byID[o.SliceID] = o
	}

	// Verify Fork 2A structural rules: C24 depends on C14 (not C23); C20 does not depend on C19.
	c24, ok := byID["C24"]
	if !ok || !slices.Equal(c24.CoreDependencies, []string{"C14"}) {
		return errors.New("sliceoracles: Fork 2A requires C24 coreDependencies to be [C14]")
	}
	c20, ok := byID["C20"]
	if !ok || slices.Contains(c20.CoreDependencies, "C19") {
		return errors.New("sliceoracles: Fork 2A requires C20 coreDependencies not to wait for C19")
	}

	// Verify all dependency references exist and form a DAG.
	visiting := make(map[string]bool, len(byID))
	visited := make(map[string]bool, len(byID))
	var dfs func(id string) error
	dfs = func(id string) error {
		if visiting[id] {
			return fmt.Errorf("sliceoracles: dependency cycle detected at %s", id)
		}
		if visited[id] {
			return nil
		}
		visiting[id] = true
		o := byID[id]
		for _, dep := range append(slices.Clone(o.CoreDependencies), o.QualDependencies...) {
			if _, exists := byID[dep]; !exists {
				return fmt.Errorf("sliceoracles: slice %s references unknown dependency %s", id, dep)
			}
			if err := dfs(dep); err != nil {
				return err
			}
		}
		visiting[id] = false
		visited[id] = true
		return nil
	}
	for id := range byID {
		if err := dfs(id); err != nil {
			return err
		}
	}
	return nil
}

// PartitionNoNewHardware splits the 32 oracles into immediately executable no-new-hardware slices
// vs slices gated on deferred Fork 3 hardware.
func (b *Batch) PartitionNoNewHardware() (noNewHW []SliceOracle, deferredHW []SliceOracle) {
	for _, o := range b.Oracles {
		if o.RequiresFork3Hardware {
			deferredHW = append(deferredHW, o)
		} else {
			noNewHW = append(noNewHW, o)
		}
	}
	return noNewHW, deferredHW
}

// ReadyNoNewHardwareQueue returns the ordered list of no-new-hardware slices (and phase "CORE" or "FULL")
// whose dependencies are satisfied given completedCORE and completedFULL sets.
func (b *Batch) ReadyNoNewHardwareQueue(completedCORE, completedFULL map[string]bool) []string {
	var ready []string
	for _, o := range b.Oracles {
		if o.RequiresFork3Hardware {
			continue
		}
		sid := o.SliceID
		if o.SplitMode {
			if !completedCORE[sid] {
				coreOK := true
				for _, dep := range o.CoreDependencies {
					if dep == "C16" {
						if !completedCORE[dep] && !completedFULL[dep] {
							coreOK = false
							break
						}
					} else if !completedFULL[dep] {
						coreOK = false
						break
					}
				}
				if coreOK {
					ready = append(ready, sid+":CORE")
				}
			} else if !completedFULL[sid] {
				qualOK := true
				for _, qdep := range o.QualDependencies {
					if !completedFULL[qdep] {
						qualOK = false
						break
					}
				}
				if qualOK {
					ready = append(ready, sid+":QUAL")
				}
			}
		} else if !completedFULL[sid] {
			depsOK := true
			for _, dep := range o.CoreDependencies {
				if !completedFULL[dep] {
					depsOK = false
					break
				}
			}
			if depsOK {
				ready = append(ready, sid+":FULL")
			}
		}
	}
	return ready
}

// ValidateConcurrentWritePRs enforces Fork 2A: at most 2 active write PRs per repository,
// targeting distinct known slices with non-overlapping repository-relative path prefixes.
func (b *Batch) ValidateConcurrentWritePRs(active []ActivePR) error {
	if len(active) > b.MaxConcurrentWritePRsPerRepo {
		return fmt.Errorf("sliceoracles: %d active write PRs exceed Fork 2A cap of %d", len(active), b.MaxConcurrentWritePRsPerRepo)
	}
	known := make(map[string]bool, len(b.Oracles))
	for _, o := range b.Oracles {
		known[o.SliceID] = true
	}
	ids := make([]string, len(active))
	paths := make([][]string, len(active))
	for i, pr := range active {
		id := strings.TrimSpace(pr.SliceID)
		if id == "" || len(pr.TouchedPaths) == 0 {
			return errors.New("sliceoracles: active PR must declare sliceId and touchedPaths")
		}
		if !known[id] {
			return fmt.Errorf("sliceoracles: active PR targets unknown slice %q", id)
		}
		ids[i] = id
		for _, p := range pr.TouchedPaths {
			clean, err := cleanTouchedPath(p)
			if err != nil {
				return fmt.Errorf("sliceoracles: slice %s: %w", id, err)
			}
			paths[i] = append(paths[i], clean)
		}
	}
	for i := range active {
		for j := i + 1; j < len(active); j++ {
			if ids[i] == ids[j] {
				return fmt.Errorf("sliceoracles: concurrent PRs target the same slice %s", ids[i])
			}
			for _, p1 := range paths[i] {
				for _, p2 := range paths[j] {
					if pathsOverlap(p1, p2) {
						return fmt.Errorf("sliceoracles: concurrent PRs (%s, %s) overlap on paths %q and %q", ids[i], ids[j], p1, p2)
					}
				}
			}
		}
	}
	return nil
}

// cleanTouchedPath returns the cleaned repository-relative form of p and rejects
// empty, absolute and repository-escaping paths.
func cleanTouchedPath(p string) (string, error) {
	trimmed := strings.TrimSpace(p)
	if trimmed == "" || strings.HasPrefix(trimmed, "/") {
		return "", fmt.Errorf("touched path %q must be a non-empty repository-relative path", p)
	}
	clean := path.Clean(trimmed)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("touched path %q must stay inside the repository", p)
	}
	return clean, nil
}

// pathsOverlap reports whether two cleaned repository-relative paths are equal or nested.
func pathsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// ValidateLKGSafety checks all 6 S1-S6 invariants required for dead-end-free autonomous self-evolution.
func ValidateLKGSafety(s LKGSafetyState) []string {
	var blockers []string
	if !s.ImmutableBootloaderVerified {
		blockers = append(blockers, "S1: immutable bootloader supervisor checksum not verified")
	}
	if s.PinnedLKGSlots < MinPinnedLKGSlots {
		blockers = append(blockers, fmt.Sprintf("S2: requires at least %d locally pinned LKG slots, got %d", MinPinnedLKGSlots, s.PinnedLKGSlots))
	}
	if s.SoakMinutes < MinSoakMinutes {
		blockers = append(blockers, fmt.Sprintf("S2: requires >= %d minutes soak before LKG promotion, got %d", MinSoakMinutes, s.SoakMinutes))
	}
	if !s.WebhookBypassVerified {
		blockers = append(blockers, "S3: rollback namespace/channel bypass of admission/conversion webhooks not verified")
	}
	if !s.PreMigrationSnapshotVerified {
		blockers = append(blockers, "S4: pre-migration state snapshot and V_old/V_new round-trip not verified")
	}
	if !s.MetaRSISelfCheckPassed {
		blockers = append(blockers, "S5: meta-RSI noop self-check canary did not pass")
	}
	if strings.TrimSpace(s.CandidateSHA) == "" {
		blockers = append(blockers, "S6: candidateSha is empty")
	} else if slices.Contains(s.QuarantinedSHAs, s.CandidateSHA) {
		blockers = append(blockers, fmt.Sprintf("S6: candidateSha %s is in incident quarantine and requires a new regression test", s.CandidateSHA))
	}
	return blockers
}

// EvaluateSliceCandidate runs autonomous Fork 1A acceptance for a slice candidate by combining
// oracle membership, hardware boundary check, S1-S6 LKG safety, and the frozen RSI G1-G7 evaluator.
func (b *Batch) EvaluateSliceCandidate(sliceID, phase string, profile rsi.CandidateProfile, lkg LKGSafetyState) (*SliceAcceptanceReceipt, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	var oracle *SliceOracle
	for i := range b.Oracles {
		if b.Oracles[i].SliceID == sliceID {
			oracle = &b.Oracles[i]
			break
		}
	}
	if oracle == nil {
		return nil, fmt.Errorf("sliceoracles: unknown slice %q", sliceID)
	}

	receipt := &SliceAcceptanceReceipt{
		SliceID: sliceID,
		Phase:   phase,
		Verdict: rsi.VerdictFail,
	}

	if oracle.RequiresFork3Hardware {
		receipt.Blockers = append(receipt.Blockers, fmt.Sprintf("Fork 3 deferred: slice %s requires additional multi-node/second-provider hardware", sliceID))
	}

	receipt.Blockers = append(receipt.Blockers, ValidateLKGSafety(lkg)...)

	rep, err := rsi.EvaluateCandidate(profile)
	if err != nil {
		return nil, err
	}
	receipt.RSIReport = &rep
	if rep.Verdict != rsi.VerdictPass {
		receipt.Blockers = append(receipt.Blockers, fmt.Sprintf("RSI G1-G7 evaluator returned verdict=%s (failed=%d, killSwitch=%s)", rep.Verdict, rep.Failed, rep.KillSwitchLevel))
	}

	if len(receipt.Blockers) == 0 {
		receipt.Verdict = rsi.VerdictPass
		receipt.PromotedToLKG = true
	}
	return receipt, nil
}
