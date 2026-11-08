// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Package rsi implements CloudRING's scientifically grounded Recursive
// Self-Improvement (RSI) governance and decision-science evaluator. It
// classifies candidate changes into autonomy classes K0-K4, evaluates the
// mandatory safety and quality gates G1-G7 under an external frozen evaluator
// contract, computes exact rational Value of Information (VOI / EVSI),
// unbiased task-averaged combinatorial pass^k and pass@k reliability,
// cluster-robust experimental design diagnostics (SRM, DEFF, non-inferiority,
// TOST), and Theory-of-Value stage-gate validation.
package rsi

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"path"
	"sort"
	"strings"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const (
	ProfileAPIVersion = "cloudring.org/rsi-governance/v1"
	ProfileKind       = "RSICandidateProfile"
	ReportSchema      = "cloudring.rsi-governance-report/v1"

	ClassK0 = "K0"
	ClassK1 = "K1"
	ClassK2 = "K2"
	ClassK3 = "K3"
	ClassK4 = "K4"

	VerdictPass = "pass"
	VerdictFail = "fail"

	StatusPass = "pass"
	StatusFail = "fail"

	KillSwitchNone = "none"
	KillSwitchL1   = "L1_suspend_gitops_canary"
	KillSwitchL2   = "L2_revoke_gateway_openbao_leases"
	KillSwitchL3   = "L3_vap_ai_freeze_deny"

	maxProfileBytes = 1 << 20
)

var (
	ErrInvalidProfile = errors.New("rsi: invalid candidate profile")

	minMutationKillScore = big.NewRat(4, 5)          // 80% diff-based mutation kill threshold (G2)
	maxCanaryStepPct     = big.NewRat(10, 100)       // 10% max initial/step canary weight for AI (G4)
	maxCanaryWeightPct   = big.NewRat(50, 100)       // 50% max canary weight before promotion (G4)
	minCanarySuccessRate = big.NewRat(99, 100)       // 99% minimum request success rate (G4)
	maxCanaryLatencyMs   = big.NewRat(500, 1)        // 500 ms maximum p99 latency during canary (G4)
	sloMonthlyBudgetMin  = big.NewRat(432, 10)       // 43.2 minutes (99.9% over 30 days)
	maxCanarySLOBurnFrac = big.NewRat(1, 10)         // at most 10% of monthly error budget per canary
	maxAICFR             = big.NewRat(3, 20)         // 15% maximum rolling AI Change Fail Rate (G6)
	maxTaskCostUSD       = big.NewRat(10, 1)         // $10.00 default cap per autonomous task (G7)
	maxTaskDurationMin   = big.NewRat(30, 1)         // 30 minutes default cap per autonomous task (G7)
	maxCostBurnMult      = big.NewRat(2, 1)          // 2x median task cost burn trigger (G7)
	srmChiSquareCrit     = big.NewRat(108276, 10000) // chi^2(1) p=0.001 critical value ~10.8276
)

// CandidateProfile declares the observable verification receipts and decision
// inputs for a candidate change evaluated by the external frozen evaluator.
type CandidateProfile struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Candidate  CandidateMetadata `json:"candidate"`
	Gates      GateReceipts      `json:"gates"`
	VOI        *VOIInput         `json:"voi,omitempty"`
	PassK      *PassKInput       `json:"passK,omitempty"`
	Experiment *ExperimentInput  `json:"experiment,omitempty"`
	Discovery  *DiscoveryInput   `json:"discovery,omitempty"`
}

// CandidateMetadata identifies the diff and declared target class.
type CandidateMetadata struct {
	ID                       string   `json:"id"`
	DeclaredClass            string   `json:"declaredClass"`
	ChangedPaths             []string `json:"changedPaths"`
	ReadOnlyOnly             bool     `json:"readOnlyOnly"`
	ReversibleConfigOnly     bool     `json:"reversibleConfigOnly"`
	DeletedOrSkippedTests    int      `json:"deletedOrSkippedTests"`
	ModifiedExistingTests    bool     `json:"modifiedExistingTests"`
	ModifiedTestdata         bool     `json:"modifiedTestdata"`
	HumanK4ApprovalReference string   `json:"humanK4ApprovalReference"`
}

// GateReceipts holds externally measured G1-G7 evidence (never self-reported by the candidate).
type GateReceipts struct {
	G1 G1Receipt `json:"g1"`
	G2 G2Receipt `json:"g2"`
	G3 G3Receipt `json:"g3"`
	G4 G4Receipt `json:"g4"`
	G5 G5Receipt `json:"g5"`
	G6 G6Receipt `json:"g6"`
	G7 G7Receipt `json:"g7"`
}

// G1Receipt captures test suite execution and anti-tampering checks.
type G1Receipt struct {
	EvaluatorFrozenHashVerified bool `json:"evaluatorFrozenHashVerified"`
	SuitePassed                 bool `json:"suitePassed"`
	NewTestFailedBeforeFix      bool `json:"newTestFailedBeforeFix"`
	NewTestPassedAfterFix       bool `json:"newTestPassedAfterFix"`
	RerunMaskingUsed            bool `json:"rerunMaskingUsed"`
	SilentErrorSwallowing       int  `json:"silentErrorSwallowing"`
	UnseenHoldoutPassed         bool `json:"unseenHoldoutPassed"`
	SeededErrorRejected         bool `json:"seededErrorRejected"`
}

// G2Receipt captures diff-based mutation testing on changed non-arid lines and fuzzing.
type G2Receipt struct {
	KilledMutants     int  `json:"killedMutants"`
	TotalMutants      int  `json:"totalMutants"`
	FuzzTargetsPassed bool `json:"fuzzTargetsPassed"`
}

// G3Receipt captures static security analysis, vulnerability scanning, and agent capability boundaries.
type G3Receipt struct {
	SASTFindings                int  `json:"sastFindings"`
	VulnFindings                int  `json:"vulnFindings"`
	ExternalCapabilityGate      bool `json:"externalCapabilityGate"`
	PromptDelimiterOnlySecurity bool `json:"promptDelimiterOnlySecurity"`
	ExplanationOnlyApproval     bool `json:"explanationOnlyApproval"`
}

// G4Receipt captures progressive canary parameters and stateful downgrade continuity.
type G4Receipt struct {
	ActiveCanaries              int    `json:"activeCanaries"`
	CanaryStepPercent           string `json:"canaryStepPercent"`
	CanaryMaxPercent            string `json:"canaryMaxPercent"`
	RequestSuccessRatePercent   string `json:"requestSuccessRatePercent"`
	LatencyP99Ms                string `json:"latencyP99Ms"`
	CanaryDurationMinutes       string `json:"canaryDurationMinutes"`
	CanaryFailuresLast24h       int    `json:"canaryFailuresLast24h"`
	TouchesPersistentState      bool   `json:"touchesPersistentState"`
	DowngradeContinuityVerified bool   `json:"downgradeContinuityVerified"`
}

// G5Receipt captures tenant portability and EU Data Act switching drill verification.
type G5Receipt struct {
	PortabilityDrillPassed bool   `json:"portabilityDrillPassed"`
	DataActVerdict         string `json:"dataActVerdict"`
}

// G6Receipt captures rolling DORA Change Fail Rate (CFR) for AI and human deployment lines.
type G6Receipt struct {
	AIFailedDeployments    int `json:"aiFailedDeployments"`
	AITotalDeployments     int `json:"aiTotalDeployments"`
	HumanFailedDeployments int `json:"humanFailedDeployments"`
	HumanTotalDeployments  int `json:"humanTotalDeployments"`
}

// G7Receipt captures compute budget, wall-clock duration, and cross-family overseer isolation.
type G7Receipt struct {
	TaskCostUSD         string `json:"taskCostUsd"`
	MedianTaskCostUSD   string `json:"medianTaskCostUsd"`
	TaskDurationMinutes string `json:"taskDurationMinutes"`
	ExecutorModelFamily string `json:"executorModelFamily"`
	OverseerModelFamily string `json:"overseerModelFamily"`
}

// VOIInput defines a Bayesian Value of Information (EVPI / EVSI) decision problem (C-20).
type VOIInput struct {
	PriorSuccessProb       string `json:"priorSuccessProb"`
	SuccessNetPayoffEUR    string `json:"successNetPayoffEur"`
	FailureLossEUR         string `json:"failureLossEur"`
	NoActionPayoffEUR      string `json:"noActionPayoffEur"`
	TestCostEUR            string `json:"testCostEur"`
	TestSensitivity        string `json:"testSensitivity"`
	TestSpecificity        string `json:"testSpecificity"`
	HardLossCapEUR         string `json:"hardLossCapEur"`
	CorrelatedLLMRunsCount int    `json:"correlatedLlmRunsCount"`
}

// VOIReport holds exact rational Bayesian decision and EVSI results.
type VOIReport struct {
	NoTestBestAction         string `json:"noTestBestAction"`
	LaunchNowEVEUR           string `json:"launchNowEvEur"`
	NoTestBestEVEUR          string `json:"noTestBestEvEur"`
	PositiveTestProb         string `json:"positiveTestProb"`
	PosteriorSuccessGivenPos string `json:"posteriorSuccessGivenPos"`
	PosteriorSuccessGivenNeg string `json:"posteriorSuccessGivenNeg"`
	EVPIEUR                  string `json:"evpiEur"`
	GrossPolicyEVEUR         string `json:"grossPolicyEvEur"`
	GrossEVSIEUR             string `json:"grossEvsiEur"`
	NetPolicyEVEUR           string `json:"netPolicyEvEur"`
	NetIncrementalEVEUR      string `json:"netIncrementalEvEur"`
	FeasibleUnderLossCap     bool   `json:"feasibleUnderLossCap"`
	EffectiveNetEVSIUnderCap string `json:"effectiveNetEvsiUnderCapEur"`
	ExtremizationRejected    bool   `json:"extremizationRejected"`
	RecommendedAction        string `json:"recommendedAction"`
}

// TaskTrialCount records n trials and c successes on task i.
type TaskTrialCount struct {
	TaskID    string `json:"taskId"`
	Trials    int    `json:"trials"`
	Successes int    `json:"successes"`
}

// PassKInput defines heterogeneous multi-trial agent evaluation and cascade economics (C-21).
type PassKInput struct {
	K                  int              `json:"k"`
	Tasks              []TaskTrialCount `json:"tasks"`
	CheapModelCostUSD  string           `json:"cheapModelCostUsd"`
	VerifierCostUSD    string           `json:"verifierCostUsd"`
	StrongModelCostUSD string           `json:"strongModelCostUsd"`
	GateFailRate       string           `json:"gateFailRate"`
	StrongRetryRate    string           `json:"strongRetryRate"`
	HumanCodingHours   string           `json:"humanCodingHours"`
	HumanReviewHours   string           `json:"humanReviewHours"`
	HumanReworkHours   string           `json:"humanReworkHours"`
	AcceptedTasks      int              `json:"acceptedTasks"`
	AttemptedTasks     int              `json:"attemptedTasks"`
}

// PassKReport holds unbiased combinatorial pass^k, pass@k, cascade cost, and labor per accepted task.
type PassKReport struct {
	K                           int    `json:"k"`
	MeanPass1                   string `json:"meanPass1"`
	UnbiasedCombinatorialPassK  string `json:"unbiasedCombinatorialPassK"`
	UnbiasedCombinatorialPassAt string `json:"unbiasedCombinatorialPassAtK"`
	NaiveHomogeneousPassK       string `json:"naiveHomogeneousPassK"`
	NaiveHomogeneousPassAtK     string `json:"naiveHomogeneousPassAtK"`
	FullCascadeCostPerTaskUSD   string `json:"fullCascadeCostPerTaskUsd"`
	NaiveCascadeCostPerTaskUSD  string `json:"naiveCascadeCostPerTaskUsd"`
	TotalHumanHours             string `json:"totalHumanHours"`
	HumanHoursPerAcceptedTask   string `json:"humanHoursPerAcceptedTask"`
	AcceptanceRate              string `json:"acceptanceRate"`
}

// ExperimentInput defines a B2B cluster/crossover experiment diagnostic check (C-19).
type ExperimentInput struct {
	ControlAssignedUnits      int    `json:"controlAssignedUnits"`
	TreatmentAssignedUnits    int    `json:"treatmentAssignedUnits"`
	ClustersPerArm            int    `json:"clustersPerArm"`
	UnitsPerCluster           int    `json:"unitsPerCluster"`
	IntraclusterCorrelation   string `json:"intraclusterCorrelation"`
	NaiveZStat                string `json:"naiveZStat"`
	HasPostTreatmentCovariate bool   `json:"hasPostTreatmentCovariate"`
	ObservedDiff              string `json:"observedDiff"`
	DiffStandardError         string `json:"diffStandardError"`
	NonInferiorityMargin      string `json:"nonInferiorityMargin"`
}

// ExperimentReport holds SRM, cluster DEFF, and non-inferiority / TOST verdicts.
type ExperimentReport struct {
	SRMChiSquare              string `json:"srmChiSquare"`
	SRMDetected               bool   `json:"srmDetected"`
	DesignEffectDEFF          string `json:"designEffectDeff"`
	EffectiveUnitsPerArm      string `json:"effectiveUnitsPerArm"`
	SEInflationFactor         string `json:"seInflationFactor"`
	ClusterAdjustedTStat      string `json:"clusterAdjustedTStat"`
	ClusterSignificantAt005   bool   `json:"clusterSignificantAt005"`
	CUPEDValid                bool   `json:"cupedValid"`
	NonInferiorityZ           string `json:"nonInferiorityZ"`
	TOSTUpperZ                string `json:"tostUpperZ"`
	NonInferiorityProvenAt005 bool   `json:"nonInferiorityProvenAt005"`
	TOSTEquivalenceProven005  bool   `json:"tostEquivalenceProvenAt005"`
	Verdict                   string `json:"verdict"`
}

// DiscoveryInput defines a Theory-of-Value stage-gate validation check (C-18).
type DiscoveryInput struct {
	HardConstraintsIntact        bool `json:"hardConstraintsIntact"`
	TotalInterviewedPeople       int  `json:"totalInterviewedPeople"`
	IndependentAccounts          int  `json:"independentAccounts"`
	HasTechnicalUserEvidence     bool `json:"hasTechnicalUserEvidence"`
	HasEconomicBuyerEvidence     bool `json:"hasEconomicBuyerEvidence"`
	HasVetoHolderEvidence        bool `json:"hasVetoHolderEvidence"`
	UsesMechanicalWTPDivisor     bool `json:"usesMechanicalWtpDivisor"`
	UsesRICEToOverrideSecurity   bool `json:"usesRiceToOverrideSecurity"`
	ExternalContactOwnerApproved bool `json:"externalContactOwnerApproved"`
	HasConsequentialCommitment   bool `json:"hasConsequentialCommitment"`
}

// DiscoveryReport holds the Theory-of-Value stage-gate evaluation.
type DiscoveryReport struct {
	AccountInflationDetected   bool     `json:"accountInflationDetected"`
	RoleStratificationComplete bool     `json:"roleStratificationComplete"`
	MethodologicallyValid      bool     `json:"methodologicallyValid"`
	StageGateAuthorized        bool     `json:"stageGateAuthorized"`
	Reasons                    []string `json:"reasons"`
}

// Classification describes the resolved autonomy class and escalation reasons.
type Classification struct {
	DeclaredClass         string   `json:"declaredClass"`
	EffectiveClass        string   `json:"effectiveClass"`
	HumanApprovalRequired bool     `json:"humanApprovalRequired"`
	HoldoutRequired       bool     `json:"holdoutRequired"`
	EscalationReasons     []string `json:"escalationReasons"`
}

// CheckResult records a single deterministic gate evaluation.
type CheckResult struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Summary string `json:"summary"`
}

// Report is the complete machine-verifiable RSI governance and decision report.
type Report struct {
	SchemaVersion         string            `json:"schemaVersion"`
	APIVersion            string            `json:"apiVersion"`
	CandidateID           string            `json:"candidateId"`
	Classification        Classification    `json:"classification"`
	Checks                []CheckResult     `json:"checks"`
	Passed                int               `json:"passed"`
	Failed                int               `json:"failed"`
	MaxAutonomousClass    string            `json:"maxAutonomousClass"`
	KillSwitchLevel       string            `json:"killSwitchLevel"`
	KillSwitchReasons     []string          `json:"killSwitchReasons"`
	MutationKillRatio     string            `json:"mutationKillRatio"`
	AIChangeFailRate      string            `json:"aiChangeFailRate"`
	HumanChangeFailRate   string            `json:"humanChangeFailRate"`
	CanarySLOBurnFraction string            `json:"canarySloBurnFraction"`
	VOI                   *VOIReport        `json:"voi,omitempty"`
	PassK                 *PassKReport      `json:"passK,omitempty"`
	Experiment            *ExperimentReport `json:"experiment,omitempty"`
	Discovery             *DiscoveryReport  `json:"discovery,omitempty"`
	Verdict               string            `json:"verdict"`
}

// ParseProfile strictly decodes a CandidateProfile from JSON bytes.
func ParseProfile(raw []byte) (CandidateProfile, error) {
	if len(raw) == 0 || len(raw) > maxProfileBytes {
		return CandidateProfile{}, fmt.Errorf("%w: profile size out of bounds", ErrInvalidProfile)
	}
	var profile CandidateProfile
	if err := strictjson.DecodeExact(raw, &profile); err != nil {
		return CandidateProfile{}, fmt.Errorf("%w: %v", ErrInvalidProfile, err)
	}
	if profile.APIVersion != ProfileAPIVersion || profile.Kind != ProfileKind {
		return CandidateProfile{}, fmt.Errorf("%w: expected apiVersion=%q kind=%q", ErrInvalidProfile, ProfileAPIVersion, ProfileKind)
	}
	if strings.TrimSpace(profile.Candidate.ID) == "" {
		return CandidateProfile{}, fmt.Errorf("%w: candidate.id is required", ErrInvalidProfile)
	}
	if !validClass(profile.Candidate.DeclaredClass) {
		return CandidateProfile{}, fmt.Errorf("%w: invalid declaredClass %q", ErrInvalidProfile, profile.Candidate.DeclaredClass)
	}
	if len(profile.Candidate.ChangedPaths) == 0 && !profile.Candidate.ReadOnlyOnly {
		return CandidateProfile{}, fmt.Errorf("%w: changedPaths required for non-K0 candidate", ErrInvalidProfile)
	}
	return profile, nil
}

func validClass(c string) bool {
	switch c {
	case ClassK0, ClassK1, ClassK2, ClassK3, ClassK4:
		return true
	default:
		return false
	}
}

func classRank(c string) int {
	switch c {
	case ClassK0:
		return 0
	case ClassK1:
		return 1
	case ClassK2:
		return 2
	case ClassK3:
		return 3
	case ClassK4:
		return 4
	default:
		return 4
	}
}

// ClassifyCandidate determines the effective change class K0-K4 and enforces
// DGM / ImpossibleBench anti-reward-hacking escalations.
func ClassifyCandidate(meta CandidateMetadata) (Classification, error) {
	if !validClass(meta.DeclaredClass) {
		return Classification{}, fmt.Errorf("%w: unknown class %q", ErrInvalidProfile, meta.DeclaredClass)
	}
	effective := meta.DeclaredClass
	var reasons []string

	touchesProd := false
	touchesTests := false
	touchesAI := false
	touchesK4 := false

	for _, rawPath := range meta.ChangedPaths {
		lowerRaw := strings.ToLower(rawPath)
		if strings.Contains(rawPath, "\x00") || strings.Contains(lowerRaw, "%2e") || strings.Contains(lowerRaw, "%2f") || strings.Contains(lowerRaw, "%5c") {
			touchesK4 = true
			reasons = append(reasons, fmt.Sprintf("encoded_or_null_path:%s", rawPath))
			continue
		}
		trimmed := strings.TrimSpace(rawPath)
		if trimmed == "" || strings.Contains(trimmed, `\`) {
			touchesK4 = true
			reasons = append(reasons, fmt.Sprintf("invalid_or_backslash_path:%s", rawPath))
			continue
		}
		cleaned := path.Clean(trimmed)
		if cleaned == "." || cleaned == "/" || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") || strings.Contains(trimmed, "..") {
			touchesK4 = true
			reasons = append(reasons, fmt.Sprintf("path_traversal_or_absolute:%s", rawPath))
			continue
		}
		lower := strings.ToLower(cleaned)
		segments := strings.Split(lower, "/")
		for _, seg := range segments {
			if seg == ".github" || seg == "evaluator" || seg == "policies" || seg == "codeowners" || seg == "openbao" || seg == "grants" || seg == "verify" {
				touchesK4 = true
				reasons = append(reasons, fmt.Sprintf("protected_k4_path:%s", lower))
				break
			}
		}
		if lower == "ops/stop" || strings.HasSuffix(lower, "/ops/stop") || strings.HasSuffix(lower, "codeowners") {
			touchesK4 = true
			reasons = append(reasons, fmt.Sprintf("protected_control_file:%s", lower))
		}
		if strings.HasPrefix(lower, "pkg/rsi/") || lower == "pkg/rsi" || strings.Contains(lower, "/rsi/") || strings.HasPrefix(lower, "skills/") || strings.HasPrefix(lower, "agents/") || strings.HasPrefix(lower, "prompts/") {
			touchesAI = true
		}
		if strings.HasSuffix(lower, "_test.go") || strings.Contains(lower, "/testdata/") || strings.HasSuffix(lower, "/testdata") {
			touchesTests = true
		} else if strings.HasSuffix(lower, ".go") || strings.HasPrefix(lower, "cmd/") || strings.HasPrefix(lower, "pkg/") || strings.HasPrefix(lower, "internal/") || strings.HasPrefix(lower, "sdk/") || strings.HasPrefix(lower, "deploy/") {
			touchesProd = true
		}
	}

	if !meta.ReadOnlyOnly && classRank(effective) < classRank(ClassK1) {
		effective = ClassK1
	}
	if (touchesProd || !meta.ReversibleConfigOnly) && !meta.ReadOnlyOnly && classRank(effective) < classRank(ClassK2) {
		effective = ClassK2
	}
	if touchesAI && classRank(effective) < classRank(ClassK3) {
		effective = ClassK3
		reasons = append(reasons, "touches_ai_or_rsi_layer_requires_k3")
	}
	if meta.DeletedOrSkippedTests > 0 {
		touchesK4 = true
		reasons = append(reasons, "deleted_or_skipped_tests_requires_k4")
	}
	if touchesProd && (meta.ModifiedExistingTests || meta.ModifiedTestdata) {
		touchesK4 = true
		reasons = append(reasons, "co_modified_production_and_existing_tests_or_testdata_requires_k4")
	}
	if touchesTests && meta.ModifiedTestdata {
		touchesK4 = true
		reasons = append(reasons, "modified_testdata_fixtures_requires_k4")
	}
	if touchesK4 {
		effective = ClassK4
	}

	sort.Strings(reasons)
	reasons = compactStrings(reasons)

	return Classification{
		DeclaredClass:         meta.DeclaredClass,
		EffectiveClass:        effective,
		HumanApprovalRequired: effective == ClassK4,
		HoldoutRequired:       classRank(effective) >= classRank(ClassK3),
		EscalationReasons:     reasons,
	}, nil
}

func compactStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(in))
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func parseNonNegativeRat(raw string, field string) (*big.Rat, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: %s is empty", ErrInvalidProfile, field)
	}
	r, ok := new(big.Rat).SetString(trimmed)
	if !ok || r.Sign() < 0 {
		return nil, fmt.Errorf("%w: %s must be a non-negative rational or decimal, got %q", ErrInvalidProfile, field, raw)
	}
	return r, nil
}

func parseSignedRat(raw string, field string) (*big.Rat, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: %s is empty", ErrInvalidProfile, field)
	}
	r, ok := new(big.Rat).SetString(trimmed)
	if !ok {
		return nil, fmt.Errorf("%w: %s must be a valid rational or decimal, got %q", ErrInvalidProfile, field, raw)
	}
	return r, nil
}

func parseProbabilityRat(raw string, field string) (*big.Rat, error) {
	r, err := parseNonNegativeRat(raw, field)
	if err != nil {
		return nil, err
	}
	if r.Cmp(big.NewRat(1, 1)) > 0 {
		return nil, fmt.Errorf("%w: %s must be in [0, 1], got %q", ErrInvalidProfile, field, raw)
	}
	return r, nil
}

// EvaluateCandidate runs the complete G1-G7 governance evaluation and any
// attached decision-science checks (VOI, PassK, Experiment, Discovery).
func EvaluateCandidate(profile CandidateProfile) (Report, error) {
	cls, err := ClassifyCandidate(profile.Candidate)
	if err != nil {
		return Report{}, err
	}

	var checks []CheckResult
	var killReasons []string
	killLevel := KillSwitchNone
	maxAutoClass := ClassK3

	// Gate K4: Human approval check when escalated or declared K4.
	k4Pass := true
	k4Summary := fmt.Sprintf("effective class %s within autonomous boundary", cls.EffectiveClass)
	if cls.EffectiveClass == ClassK4 {
		if strings.TrimSpace(profile.Candidate.HumanK4ApprovalReference) == "" {
			k4Pass = false
			k4Summary = fmt.Sprintf("effective class K4 requires explicit human approval (%s)", strings.Join(cls.EscalationReasons, ", "))
			if profile.Candidate.DeletedOrSkippedTests > 0 || profile.Candidate.ModifiedExistingTests || profile.Candidate.ModifiedTestdata {
				killLevel = escalateKillSwitch(killLevel, KillSwitchL3)
				killReasons = append(killReasons, "test_or_evaluator_tampering_detected")
			}
		} else {
			k4Summary = fmt.Sprintf("effective class K4 authorized by human reference %s", profile.Candidate.HumanK4ApprovalReference)
		}
	}
	checks = append(checks, makeCheck("k4_human_boundary", k4Pass, k4Summary))

	// Gate G1: Red->Green test & evaluator hash integrity.
	g1 := profile.Gates.G1
	g1Pass := g1.EvaluatorFrozenHashVerified && g1.SuitePassed && !g1.RerunMaskingUsed && g1.SilentErrorSwallowing == 0
	if classRank(cls.EffectiveClass) >= classRank(ClassK2) {
		g1Pass = g1Pass && g1.NewTestFailedBeforeFix && g1.NewTestPassedAfterFix
	}
	if cls.HoldoutRequired {
		g1Pass = g1Pass && g1.UnseenHoldoutPassed && g1.SeededErrorRejected
	}
	g1Summary := fmt.Sprintf("frozenHash=%t suite=%t redGreen=%t/%t holdout=%t seededError=%t rerunMask=%t silentSwallow=%d",
		g1.EvaluatorFrozenHashVerified, g1.SuitePassed, g1.NewTestFailedBeforeFix, g1.NewTestPassedAfterFix,
		g1.UnseenHoldoutPassed, g1.SeededErrorRejected, g1.RerunMaskingUsed, g1.SilentErrorSwallowing)
	checks = append(checks, makeCheck("g1_red_green_and_test_integrity", g1Pass, g1Summary))

	// Gate G2: Diff-based mutation score >= 80% and fuzz targets.
	g2 := profile.Gates.G2
	mutRatio := big.NewRat(0, 1)
	g2Pass := g2.FuzzTargetsPassed
	if classRank(cls.EffectiveClass) >= classRank(ClassK2) {
		if g2.TotalMutants <= 0 || g2.KilledMutants < 0 || g2.KilledMutants > g2.TotalMutants {
			g2Pass = false
		} else {
			mutRatio = big.NewRat(int64(g2.KilledMutants), int64(g2.TotalMutants))
			if mutRatio.Cmp(minMutationKillScore) < 0 {
				g2Pass = false
			}
		}
	} else if g2.TotalMutants > 0 && g2.KilledMutants >= 0 && g2.KilledMutants <= g2.TotalMutants {
		mutRatio = big.NewRat(int64(g2.KilledMutants), int64(g2.TotalMutants))
	}
	g2Summary := fmt.Sprintf("killed=%d/%d (%s) fuzzPassed=%t", g2.KilledMutants, g2.TotalMutants, mutRatio.FloatString(4), g2.FuzzTargetsPassed)
	checks = append(checks, makeCheck("g2_diff_mutation_and_fuzz", g2Pass, g2Summary))

	// Gate G3: Security SAST, govulncheck, and external capability boundary.
	g3 := profile.Gates.G3
	g3Pass := g3.SASTFindings == 0 && g3.VulnFindings == 0 && g3.ExternalCapabilityGate && !g3.PromptDelimiterOnlySecurity && !g3.ExplanationOnlyApproval
	g3Summary := fmt.Sprintf("sast=%d vuln=%d externalCapGate=%t delimiterOnly=%t explanationOnly=%t",
		g3.SASTFindings, g3.VulnFindings, g3.ExternalCapabilityGate, g3.PromptDelimiterOnlySecurity, g3.ExplanationOnlyApproval)
	checks = append(checks, makeCheck("g3_security_and_capability_boundary", g3Pass, g3Summary))

	// Gate G4: Canary SLO burn and stateful downgrade continuity.
	g4 := profile.Gates.G4
	stepPct, err := parseNonNegativeRat(g4.CanaryStepPercent, "gates.g4.canaryStepPercent")
	if err != nil {
		return Report{}, err
	}
	maxPct, err := parseNonNegativeRat(g4.CanaryMaxPercent, "gates.g4.canaryMaxPercent")
	if err != nil {
		return Report{}, err
	}
	succPct, err := parseNonNegativeRat(g4.RequestSuccessRatePercent, "gates.g4.requestSuccessRatePercent")
	if err != nil {
		return Report{}, err
	}
	latMs, err := parseNonNegativeRat(g4.LatencyP99Ms, "gates.g4.latencyP99Ms")
	if err != nil {
		return Report{}, err
	}
	durMin, err := parseNonNegativeRat(g4.CanaryDurationMinutes, "gates.g4.canaryDurationMinutes")
	if err != nil {
		return Report{}, err
	}
	stepFrac := new(big.Rat).Quo(stepPct, big.NewRat(100, 1))
	maxFrac := new(big.Rat).Quo(maxPct, big.NewRat(100, 1))
	succFrac := new(big.Rat).Quo(succPct, big.NewRat(100, 1))
	// Worst-case error-minutes during one canary step = stepFrac * durMin; burn fraction = (stepFrac * durMin) / 43.2
	errMinutes := new(big.Rat).Mul(stepFrac, durMin)
	burnFrac := new(big.Rat).Quo(errMinutes, sloMonthlyBudgetMin)

	g4Pass := g4.ActiveCanaries >= 1 && g4.ActiveCanaries <= 1 &&
		stepFrac.Cmp(maxCanaryStepPct) <= 0 &&
		maxFrac.Cmp(maxCanaryWeightPct) <= 0 &&
		succFrac.Cmp(minCanarySuccessRate) >= 0 &&
		latMs.Cmp(maxCanaryLatencyMs) <= 0 &&
		burnFrac.Cmp(maxCanarySLOBurnFrac) <= 0 &&
		g4.CanaryFailuresLast24h < 3 &&
		(!g4.TouchesPersistentState || g4.DowngradeContinuityVerified)

	if g4.CanaryFailuresLast24h >= 3 {
		killLevel = escalateKillSwitch(killLevel, KillSwitchL1)
		killReasons = append(killReasons, "three_or_more_canary_failures_in_24h")
	}
	g4Summary := fmt.Sprintf("active=%d step=%s%% max=%s%% success=%s%% p99=%sms burnFrac=%s stateful=%t downgradeOK=%t",
		g4.ActiveCanaries, stepPct.FloatString(1), maxPct.FloatString(1), succPct.FloatString(2), latMs.FloatString(1),
		burnFrac.FloatString(4), g4.TouchesPersistentState, g4.DowngradeContinuityVerified)
	checks = append(checks, makeCheck("g4_canary_slo_and_stateful_downgrade", g4Pass, g4Summary))

	// Gate G5: Portability and EU Data Act switching drill.
	g5 := profile.Gates.G5
	g5Pass := g5.PortabilityDrillPassed && g5.DataActVerdict == VerdictPass
	g5Summary := fmt.Sprintf("portabilityDrill=%t dataActVerdict=%s", g5.PortabilityDrillPassed, g5.DataActVerdict)
	checks = append(checks, makeCheck("g5_portability_and_switching_drill", g5Pass, g5Summary))

	// Gate G6: Rolling DORA Change Fail Rate (CFR) circuit breaker.
	g6 := profile.Gates.G6
	aiCFR := big.NewRat(0, 1)
	humanCFR := big.NewRat(0, 1)
	g6Pass := true
	if g6.AITotalDeployments <= 0 || g6.AIFailedDeployments < 0 || g6.AIFailedDeployments > g6.AITotalDeployments ||
		g6.HumanTotalDeployments < 0 || g6.HumanFailedDeployments < 0 || g6.HumanFailedDeployments > g6.HumanTotalDeployments {
		g6Pass = false
	} else {
		aiCFR = big.NewRat(int64(g6.AIFailedDeployments), int64(g6.AITotalDeployments))
		if aiCFR.Cmp(maxAICFR) > 0 {
			g6Pass = false
		}
		if g6.HumanTotalDeployments > 0 {
			humanCFR = big.NewRat(int64(g6.HumanFailedDeployments), int64(g6.HumanTotalDeployments))
			if aiCFR.Cmp(humanCFR) > 0 {
				g6Pass = false
			}
		}
	}
	if !g6Pass {
		maxAutoClass = ClassK1
		killLevel = escalateKillSwitch(killLevel, KillSwitchL1)
		killReasons = append(killReasons, "g6_cfr_budget_exceeded_autonomy_downgraded_to_k1")
	}
	g6Summary := fmt.Sprintf("aiCFR=%d/%d (%s) humanCFR=%d/%d (%s) maxAutoClass=%s",
		g6.AIFailedDeployments, g6.AITotalDeployments, aiCFR.FloatString(4),
		g6.HumanFailedDeployments, g6.HumanTotalDeployments, humanCFR.FloatString(4), maxAutoClass)
	checks = append(checks, makeCheck("g6_dora_cfr_circuit_breaker", g6Pass, g6Summary))

	// Gate G7: Task budget, duration, burn multiplier, and cross-family overseer.
	g7 := profile.Gates.G7
	costUSD, err := parseNonNegativeRat(g7.TaskCostUSD, "gates.g7.taskCostUsd")
	if err != nil {
		return Report{}, err
	}
	medCostUSD, err := parseNonNegativeRat(g7.MedianTaskCostUSD, "gates.g7.medianTaskCostUsd")
	if err != nil {
		return Report{}, err
	}
	taskDurMin, err := parseNonNegativeRat(g7.TaskDurationMinutes, "gates.g7.taskDurationMinutes")
	if err != nil {
		return Report{}, err
	}
	execFam := strings.ToLower(strings.TrimSpace(g7.ExecutorModelFamily))
	overFam := strings.ToLower(strings.TrimSpace(g7.OverseerModelFamily))
	burnLimit := new(big.Rat).Mul(medCostUSD, maxCostBurnMult)
	burnExceeded := medCostUSD.Sign() <= 0 || costUSD.Cmp(burnLimit) > 0
	if burnExceeded {
		killLevel = escalateKillSwitch(killLevel, KillSwitchL2)
		killReasons = append(killReasons, "g7_task_cost_burn_exceeded_2x_median")
	}
	g7Pass := costUSD.Cmp(maxTaskCostUSD) <= 0 &&
		taskDurMin.Cmp(maxTaskDurationMin) <= 0 &&
		!burnExceeded &&
		execFam != "" && overFam != "" && execFam != overFam
	g7Summary := fmt.Sprintf("cost=$%s (median=$%s) duration=%smin executor=%s overseer=%s",
		costUSD.FloatString(2), medCostUSD.FloatString(2), taskDurMin.FloatString(1), execFam, overFam)
	checks = append(checks, makeCheck("g7_budget_and_cross_family_overseer", g7Pass, g7Summary))

	var voiReport *VOIReport
	if profile.VOI != nil {
		vr, err := EvaluateVOI(*profile.VOI)
		if err != nil {
			return Report{}, err
		}
		voiReport = &vr
		voiPass := vr.ExtremizationRejected && (vr.FeasibleUnderLossCap || vr.RecommendedAction == "do_not_launch_or_test_until_loss_restructured")
		checks = append(checks, makeCheck("c20_voi_and_loss_cap", voiPass,
			fmt.Sprintf("netEVSI=%s EUR feasibleUnderCap=%t action=%s", vr.NetIncrementalEVEUR, vr.FeasibleUnderLossCap, vr.RecommendedAction)))
	}

	var passKReport *PassKReport
	if profile.PassK != nil {
		pr, err := EvaluatePassK(*profile.PassK)
		if err != nil {
			return Report{}, err
		}
		passKReport = &pr
		checks = append(checks, makeCheck("c21_combinatorial_passk_and_cascade_cost", true,
			fmt.Sprintf("pass^%d=%s pass@%d=%s fullCascade=$%s hoursPerAccepted=%s",
				pr.K, pr.UnbiasedCombinatorialPassK, pr.K, pr.UnbiasedCombinatorialPassAt, pr.FullCascadeCostPerTaskUSD, pr.HumanHoursPerAcceptedTask)))
	}

	var expReport *ExperimentReport
	if profile.Experiment != nil {
		er, err := EvaluateExperiment(*profile.Experiment)
		if err != nil {
			return Report{}, err
		}
		expReport = &er
		expPass := !er.SRMDetected && er.CUPEDValid
		checks = append(checks, makeCheck("c19_experiment_srm_deff_tost", expPass,
			fmt.Sprintf("srmChi2=%s deff=%s tCluster=%s cupedValid=%t verdict=%s",
				er.SRMChiSquare, er.DesignEffectDEFF, er.ClusterAdjustedTStat, er.CUPEDValid, er.Verdict)))
	}

	var discReport *DiscoveryReport
	if profile.Discovery != nil {
		dr, err := EvaluateDiscovery(*profile.Discovery)
		if err != nil {
			return Report{}, err
		}
		discReport = &dr
		checks = append(checks, makeCheck("c18_theory_of_value_stage_gate", dr.MethodologicallyValid,
			fmt.Sprintf("valid=%t authorized=%t reasons=%v", dr.MethodologicallyValid, dr.StageGateAuthorized, dr.Reasons)))
	}

	passed := 0
	failed := 0
	for _, c := range checks {
		if c.Status == StatusPass {
			passed++
		} else {
			failed++
		}
	}
	if classRank(cls.EffectiveClass) > classRank(maxAutoClass) && cls.EffectiveClass != ClassK4 {
		failed++
		checks = append(checks, makeCheck("autonomy_ceiling_enforcement", false,
			fmt.Sprintf("candidate requires %s but current maxAutonomousClass is %s", cls.EffectiveClass, maxAutoClass)))
	}

	verdict := VerdictPass
	if failed > 0 {
		verdict = VerdictFail
	}
	sort.Strings(killReasons)
	killReasons = compactStrings(killReasons)

	return Report{
		SchemaVersion:         ReportSchema,
		APIVersion:            ProfileAPIVersion,
		CandidateID:           profile.Candidate.ID,
		Classification:        cls,
		Checks:                checks,
		Passed:                passed,
		Failed:                failed,
		MaxAutonomousClass:    maxAutoClass,
		KillSwitchLevel:       killLevel,
		KillSwitchReasons:     killReasons,
		MutationKillRatio:     mutRatio.RatString(),
		AIChangeFailRate:      aiCFR.RatString(),
		HumanChangeFailRate:   humanCFR.RatString(),
		CanarySLOBurnFraction: burnFrac.RatString(),
		VOI:                   voiReport,
		PassK:                 passKReport,
		Experiment:            expReport,
		Discovery:             discReport,
		Verdict:               verdict,
	}, nil
}

func makeCheck(id string, pass bool, summary string) CheckResult {
	status := StatusFail
	if pass {
		status = StatusPass
	}
	return CheckResult{ID: id, Status: status, Summary: summary}
}

func escalateKillSwitch(current, candidate string) string {
	rank := map[string]int{
		KillSwitchNone: 0,
		KillSwitchL1:   1,
		KillSwitchL2:   2,
		KillSwitchL3:   3,
	}
	if rank[candidate] > rank[current] {
		return candidate
	}
	return current
}

// EvaluateVOI computes exact rational Bayesian posteriors, EVPI, Gross EVSI,
// Net EVSI, and enforces non-compensatory lexicographic loss caps (C-20).
func EvaluateVOI(in VOIInput) (VOIReport, error) {
	p, err := parseProbabilityRat(in.PriorSuccessProb, "voi.priorSuccessProb")
	if err != nil {
		return VOIReport{}, err
	}
	if p.Sign() == 0 || p.Cmp(big.NewRat(1, 1)) == 0 {
		return VOIReport{}, fmt.Errorf("%w: voi.priorSuccessProb must be strictly in (0, 1)", ErrInvalidProfile)
	}
	win, err := parseNonNegativeRat(in.SuccessNetPayoffEUR, "voi.successNetPayoffEur")
	if err != nil {
		return VOIReport{}, err
	}
	lossMag, err := parseNonNegativeRat(in.FailureLossEUR, "voi.failureLossEur")
	if err != nil {
		return VOIReport{}, err
	}
	noAct, err := parseSignedRat(in.NoActionPayoffEUR, "voi.noActionPayoffEur")
	if err != nil {
		return VOIReport{}, err
	}
	testCost, err := parseNonNegativeRat(in.TestCostEUR, "voi.testCostEur")
	if err != nil {
		return VOIReport{}, err
	}
	sens, err := parseProbabilityRat(in.TestSensitivity, "voi.testSensitivity")
	if err != nil {
		return VOIReport{}, err
	}
	spec, err := parseProbabilityRat(in.TestSpecificity, "voi.testSpecificity")
	if err != nil {
		return VOIReport{}, err
	}
	capEUR, err := parseNonNegativeRat(in.HardLossCapEUR, "voi.hardLossCapEur")
	if err != nil {
		return VOIReport{}, err
	}

	one := big.NewRat(1, 1)
	q := new(big.Rat).Sub(one, p)

	// Launch EV = p * win - (1-p) * lossMag
	launchEV := new(big.Rat).Sub(new(big.Rat).Mul(p, win), new(big.Rat).Mul(q, lossMag))
	noTestBestEV := new(big.Rat).Set(noAct)
	noTestAction := "do_not_launch"
	if launchEV.Cmp(noAct) > 0 {
		noTestBestEV.Set(launchEV)
		noTestAction = "launch_now"
	}

	// P(T+) = p*sens + (1-p)*(1-spec)
	fpr := new(big.Rat).Sub(one, spec)
	pPos := new(big.Rat).Add(new(big.Rat).Mul(p, sens), new(big.Rat).Mul(q, fpr))
	pNeg := new(big.Rat).Sub(one, pPos)
	if pPos.Sign() <= 0 || pNeg.Sign() <= 0 {
		return VOIReport{}, fmt.Errorf("%w: degenerate test probabilities P(T+)=%s", ErrInvalidProfile, pPos.RatString())
	}

	postPos := new(big.Rat).Quo(new(big.Rat).Mul(p, sens), pPos)
	fnr := new(big.Rat).Sub(one, sens)
	postNeg := new(big.Rat).Quo(new(big.Rat).Mul(p, fnr), pNeg)

	evGivenPos := new(big.Rat).Sub(new(big.Rat).Mul(postPos, win), new(big.Rat).Mul(new(big.Rat).Sub(one, postPos), lossMag))
	bestGivenPos := maxRat(evGivenPos, noAct)
	evGivenNeg := new(big.Rat).Sub(new(big.Rat).Mul(postNeg, win), new(big.Rat).Mul(new(big.Rat).Sub(one, postNeg), lossMag))
	bestGivenNeg := maxRat(evGivenNeg, noAct)

	grossPolicyEV := new(big.Rat).Add(new(big.Rat).Mul(pPos, bestGivenPos), new(big.Rat).Mul(pNeg, bestGivenNeg))
	grossEVSI := new(big.Rat).Sub(grossPolicyEV, noTestBestEV)
	netPolicyEV := new(big.Rat).Sub(grossPolicyEV, testCost)
	netIncrementalEV := new(big.Rat).Sub(grossEVSI, testCost)

	// Perfect information EV = p * max(win, noAct) + (1-p) * max(-lossMag, noAct)
	negLoss := new(big.Rat).Neg(lossMag)
	perfectEV := new(big.Rat).Add(new(big.Rat).Mul(p, maxRat(win, noAct)), new(big.Rat).Mul(q, maxRat(negLoss, noAct)))
	evpi := new(big.Rat).Sub(perfectEV, noTestBestEV)

	feasibleUnderCap := lossMag.Cmp(capEUR) <= 0
	effectiveNetEVSI := new(big.Rat).Set(netIncrementalEV)
	recAction := noTestAction
	if !feasibleUnderCap {
		// Non-compensatory lexicographic constraint: launch is infeasible regardless of test signal.
		effectiveNetEVSI = new(big.Rat).Neg(testCost)
		recAction = "do_not_launch_or_test_until_loss_restructured"
	} else if netIncrementalEV.Sign() > 0 {
		recAction = "run_test_and_follow_posterior_threshold"
	}

	return VOIReport{
		NoTestBestAction:         noTestAction,
		LaunchNowEVEUR:           ratToCleanString(launchEV),
		NoTestBestEVEUR:          ratToCleanString(noTestBestEV),
		PositiveTestProb:         pPos.RatString(),
		PosteriorSuccessGivenPos: postPos.RatString(),
		PosteriorSuccessGivenNeg: postNeg.RatString(),
		EVPIEUR:                  ratToCleanString(evpi),
		GrossPolicyEVEUR:         ratToCleanString(grossPolicyEV),
		GrossEVSIEUR:             ratToCleanString(grossEVSI),
		NetPolicyEVEUR:           ratToCleanString(netPolicyEV),
		NetIncrementalEVEUR:      ratToCleanString(netIncrementalEV),
		FeasibleUnderLossCap:     feasibleUnderCap,
		EffectiveNetEVSIUnderCap: ratToCleanString(effectiveNetEVSI),
		ExtremizationRejected:    in.CorrelatedLLMRunsCount >= 0,
		RecommendedAction:        recAction,
	}, nil
}

func maxRat(a, b *big.Rat) *big.Rat {
	if a.Cmp(b) >= 0 {
		return new(big.Rat).Set(a)
	}
	return new(big.Rat).Set(b)
}

func ratToCleanString(r *big.Rat) string {
	if r.IsInt() {
		return r.Num().String()
	}
	return r.RatString()
}

func binom(n, k int) *big.Int {
	if k < 0 || k > n {
		return big.NewInt(0)
	}
	return new(big.Int).Binomial(int64(n), int64(k))
}

// EvaluatePassK computes Yao et al. unbiased task-averaged combinatorial pass^k
// and pass@k, full cascade cost with retry amplification, and quality-adjusted
// human labor per accepted task (C-21).
func EvaluatePassK(in PassKInput) (PassKReport, error) {
	if in.K <= 0 || len(in.Tasks) == 0 {
		return PassKReport{}, fmt.Errorf("%w: passK requires k >= 1 and non-empty tasks", ErrInvalidProfile)
	}
	sumPass1 := big.NewRat(0, 1)
	sumPassK := big.NewRat(0, 1)
	sumPassAtK := big.NewRat(0, 1)

	for _, t := range in.Tasks {
		if t.Trials < in.K || t.Successes < 0 || t.Successes > t.Trials {
			return PassKReport{}, fmt.Errorf("%w: invalid task %q trials=%d successes=%d for k=%d", ErrInvalidProfile, t.TaskID, t.Trials, t.Successes, in.K)
		}
		sumPass1.Add(sumPass1, big.NewRat(int64(t.Successes), int64(t.Trials)))
		denom := binom(t.Trials, in.K)
		numPassK := binom(t.Successes, in.K)
		taskPassK := new(big.Rat).SetFrac(numPassK, denom)
		sumPassK.Add(sumPassK, taskPassK)

		numFailAll := binom(t.Trials-t.Successes, in.K)
		taskFailAll := new(big.Rat).SetFrac(numFailAll, denom)
		taskPassAtK := new(big.Rat).Sub(big.NewRat(1, 1), taskFailAll)
		sumPassAtK.Add(sumPassAtK, taskPassAtK)
	}

	mRat := big.NewRat(int64(len(in.Tasks)), 1)
	meanP := new(big.Rat).Quo(sumPass1, mRat)
	unbiasedPassK := new(big.Rat).Quo(sumPassK, mRat)
	unbiasedPassAtK := new(big.Rat).Quo(sumPassAtK, mRat)

	naivePassK := powRat(meanP, in.K)
	oneMinusP := new(big.Rat).Sub(big.NewRat(1, 1), meanP)
	naivePassAtK := new(big.Rat).Sub(big.NewRat(1, 1), powRat(oneMinusP, in.K))

	cCheap, err := parseNonNegativeRat(in.CheapModelCostUSD, "passK.cheapModelCostUsd")
	if err != nil {
		return PassKReport{}, err
	}
	cVer, err := parseNonNegativeRat(in.VerifierCostUSD, "passK.verifierCostUsd")
	if err != nil {
		return PassKReport{}, err
	}
	cStrong, err := parseNonNegativeRat(in.StrongModelCostUSD, "passK.strongModelCostUsd")
	if err != nil {
		return PassKReport{}, err
	}
	pFail, err := parseProbabilityRat(in.GateFailRate, "passK.gateFailRate")
	if err != nil {
		return PassKReport{}, err
	}
	rRetry, err := parseNonNegativeRat(in.StrongRetryRate, "passK.strongRetryRate")
	if err != nil {
		return PassKReport{}, err
	}

	// Full post-generation cascade cost = cCheap + cVer + pFail * cStrong * (1 + rRetry)
	retryFactor := new(big.Rat).Add(big.NewRat(1, 1), rRetry)
	strongExpected := new(big.Rat).Mul(new(big.Rat).Mul(pFail, cStrong), retryFactor)
	fullCascade := new(big.Rat).Add(new(big.Rat).Add(cCheap, cVer), strongExpected)

	// Naive weighted average often ignores verifier overhead and retries: (1 - pFail)*cCheap + pFail*cStrong
	oneMinusFail := new(big.Rat).Sub(big.NewRat(1, 1), pFail)
	naiveCascade := new(big.Rat).Add(new(big.Rat).Mul(oneMinusFail, cCheap), new(big.Rat).Mul(pFail, cStrong))

	hCode, err := parseNonNegativeRat(in.HumanCodingHours, "passK.humanCodingHours")
	if err != nil {
		return PassKReport{}, err
	}
	hRev, err := parseNonNegativeRat(in.HumanReviewHours, "passK.humanReviewHours")
	if err != nil {
		return PassKReport{}, err
	}
	hRew, err := parseNonNegativeRat(in.HumanReworkHours, "passK.humanReworkHours")
	if err != nil {
		return PassKReport{}, err
	}
	if in.AcceptedTasks <= 0 || in.AttemptedTasks < in.AcceptedTasks {
		return PassKReport{}, fmt.Errorf("%w: invalid acceptedTasks=%d attemptedTasks=%d", ErrInvalidProfile, in.AcceptedTasks, in.AttemptedTasks)
	}
	totalHours := new(big.Rat).Add(new(big.Rat).Add(hCode, hRev), hRew)
	hoursPerAccepted := new(big.Rat).Quo(totalHours, big.NewRat(int64(in.AcceptedTasks), 1))
	accRate := big.NewRat(int64(in.AcceptedTasks), int64(in.AttemptedTasks))

	return PassKReport{
		K:                           in.K,
		MeanPass1:                   meanP.RatString(),
		UnbiasedCombinatorialPassK:  unbiasedPassK.RatString(),
		UnbiasedCombinatorialPassAt: unbiasedPassAtK.RatString(),
		NaiveHomogeneousPassK:       naivePassK.RatString(),
		NaiveHomogeneousPassAtK:     naivePassAtK.RatString(),
		FullCascadeCostPerTaskUSD:   fullCascade.FloatString(2),
		NaiveCascadeCostPerTaskUSD:  naiveCascade.FloatString(2),
		TotalHumanHours:             ratToCleanString(totalHours),
		HumanHoursPerAcceptedTask:   hoursPerAccepted.RatString(),
		AcceptanceRate:              accRate.RatString(),
	}, nil
}

func powRat(base *big.Rat, exp int) *big.Rat {
	num := new(big.Int).Exp(base.Num(), big.NewInt(int64(exp)), nil)
	den := new(big.Int).Exp(base.Denom(), big.NewInt(int64(exp)), nil)
	return new(big.Rat).SetFrac(num, den)
}

// EvaluateExperiment computes SRM chi-square, cluster DEFF, effective sample
// size, and one-sided non-inferiority vs two-sided TOST equivalence (C-19).
func EvaluateExperiment(in ExperimentInput) (ExperimentReport, error) {
	if in.ControlAssignedUnits <= 0 || in.TreatmentAssignedUnits <= 0 {
		return ExperimentReport{}, fmt.Errorf("%w: assigned unit counts must be positive", ErrInvalidProfile)
	}
	if in.ClustersPerArm < 2 || in.UnitsPerCluster < 1 {
		return ExperimentReport{}, fmt.Errorf("%w: clustersPerArm >= 2 and unitsPerCluster >= 1 required", ErrInvalidProfile)
	}
	rho, err := parseProbabilityRat(in.IntraclusterCorrelation, "experiment.intraclusterCorrelation")
	if err != nil {
		return ExperimentReport{}, err
	}
	zNaive, err := parseSignedRat(in.NaiveZStat, "experiment.naiveZStat")
	if err != nil {
		return ExperimentReport{}, err
	}
	diff, err := parseSignedRat(in.ObservedDiff, "experiment.observedDiff")
	if err != nil {
		return ExperimentReport{}, err
	}
	se, err := parseNonNegativeRat(in.DiffStandardError, "experiment.diffStandardError")
	if err != nil || se.Sign() == 0 {
		return ExperimentReport{}, fmt.Errorf("%w: diffStandardError must be strictly positive", ErrInvalidProfile)
	}
	margin, err := parseNonNegativeRat(in.NonInferiorityMargin, "experiment.nonInferiorityMargin")
	if err != nil || margin.Sign() == 0 {
		return ExperimentReport{}, fmt.Errorf("%w: nonInferiorityMargin must be strictly positive", ErrInvalidProfile)
	}

	// SRM chi^2 for 50/50 split: (N_C - N_T)^2 / (N_C + N_T)
	totalUnits := int64(in.ControlAssignedUnits + in.TreatmentAssignedUnits)
	diffUnits := int64(in.ControlAssignedUnits - in.TreatmentAssignedUnits)
	srmChi2 := big.NewRat(diffUnits*diffUnits, totalUnits)
	srmDetected := srmChi2.Cmp(srmChiSquareCrit) >= 0

	// DEFF = 1 + (m - 1) * rho
	mMinus1 := big.NewRat(int64(in.UnitsPerCluster-1), 1)
	deff := new(big.Rat).Add(big.NewRat(1, 1), new(big.Rat).Mul(mMinus1, rho))
	rawArmN := big.NewRat(int64(in.ClustersPerArm*in.UnitsPerCluster), 1)
	nEff := new(big.Rat).Quo(rawArmN, deff)

	deffFloat, _ := deff.Float64()
	seInflation := math.Sqrt(deffFloat)
	zNaiveFloat, _ := zNaive.Float64()
	tCluster := zNaiveFloat / seInflation

	// Approximate two-sided p < 0.05 critical value for df = 2*(ClustersPerArm - 1)
	df := 2 * (in.ClustersPerArm - 1)
	tCrit := approximateTCrit005TwoSided(df)
	clusterSig := math.Abs(tCluster) >= tCrit && !srmDetected && !in.HasPostTreatmentCovariate

	// Non-inferiority against -margin: z_NI = (diff - (-margin)) / se = (diff + margin) / se
	zNI := new(big.Rat).Quo(new(big.Rat).Add(diff, margin), se)
	// TOST upper against +margin: z_upper = (diff - margin) / se
	zUpper := new(big.Rat).Quo(new(big.Rat).Sub(diff, margin), se)

	zNIFloat, _ := zNI.Float64()
	zUpperFloat, _ := zUpper.Float64()
	// One-sided alpha=0.05 z-critical = 1.6448536
	niProven := zNIFloat >= 1.6448536 && !srmDetected
	tostProven := zNIFloat >= 1.6448536 && zUpperFloat <= -1.6448536 && !srmDetected

	verdict := VerdictPass
	if srmDetected || in.HasPostTreatmentCovariate {
		verdict = VerdictFail
	}

	return ExperimentReport{
		SRMChiSquare:              srmChi2.FloatString(4),
		SRMDetected:               srmDetected,
		DesignEffectDEFF:          deff.FloatString(4),
		EffectiveUnitsPerArm:      nEff.FloatString(2),
		SEInflationFactor:         fmt.Sprintf("%.4f", seInflation),
		ClusterAdjustedTStat:      fmt.Sprintf("%.4f", tCluster),
		ClusterSignificantAt005:   clusterSig,
		CUPEDValid:                !in.HasPostTreatmentCovariate,
		NonInferiorityZ:           zNI.FloatString(4),
		TOSTUpperZ:                zUpper.FloatString(4),
		NonInferiorityProvenAt005: niProven,
		TOSTEquivalenceProven005:  tostProven,
		Verdict:                   verdict,
	}, nil
}

func approximateTCrit005TwoSided(df int) float64 {
	if df <= 1 {
		return 12.706
	}
	// Peizer-Pratt / Cornish-Fisher expansion for t_{0.975, df}
	z := 1.959963984540054
	d := float64(df)
	g1 := (z*z*z + z) / 4.0
	g2 := (5*math.Pow(z, 5) + 16*z*z*z + 3*z) / 96.0
	return z + g1/d + g2/(d*d)
}

// EvaluateDiscovery checks a product discovery and stage-gate packet against C-18 invariants.
func EvaluateDiscovery(in DiscoveryInput) (DiscoveryReport, error) {
	if in.TotalInterviewedPeople < 0 || in.IndependentAccounts < 0 || in.IndependentAccounts > in.TotalInterviewedPeople {
		return DiscoveryReport{}, fmt.Errorf("%w: invalid interview/account counts", ErrInvalidProfile)
	}
	accountInflation := in.TotalInterviewedPeople > in.IndependentAccounts && in.IndependentAccounts < 5
	roleComplete := in.HasTechnicalUserEvidence && in.HasEconomicBuyerEvidence && in.HasVetoHolderEvidence

	var reasons []string
	if !in.HardConstraintsIntact {
		reasons = append(reasons, "hard_architectural_or_security_constraints_violated")
	}
	if accountInflation {
		reasons = append(reasons, "multiple_interviewees_in_same_firm_counted_as_independent_accounts")
	}
	if !roleComplete {
		reasons = append(reasons, "missing_stratified_evidence_across_user_buyer_and_veto_holder")
	}
	if in.UsesMechanicalWTPDivisor {
		reasons = append(reasons, "mechanical_hypothetical_wtp_divisor_is_invalid")
	}
	if in.UsesRICEToOverrideSecurity {
		reasons = append(reasons, "rice_score_cannot_override_security_or_isolation")
	}
	if !in.ExternalContactOwnerApproved {
		reasons = append(reasons, "external_contact_requires_explicit_owner_approval")
	}
	if !in.HasConsequentialCommitment {
		reasons = append(reasons, "praise_without_consequential_migration_or_pilot_commitment")
	}

	valid := len(reasons) == 0
	return DiscoveryReport{
		AccountInflationDetected:   accountInflation,
		RoleStratificationComplete: roleComplete,
		MethodologicallyValid:      valid,
		StageGateAuthorized:        valid && in.HasConsequentialCommitment && in.ExternalContactOwnerApproved,
		Reasons:                    reasons,
	}, nil
}
