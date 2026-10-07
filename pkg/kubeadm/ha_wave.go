// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package kubeadm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/kubeidentity"
	"github.com/opencloudtech/CloudRING/pkg/resilience/oneserverloss"
)

const (
	// HAWaveSchemaVersion is the versioned, provider-neutral evidence contract
	// for one-member-at-a-time kubeadm control-plane expansion.
	HAWaveSchemaVersion = "cloudring.kubeadm.ha-wave/v2"
	// HAWaveInventorySchemaVersion is the identity-bound captured topology
	// receipt consumed by VerifyHAWave.
	HAWaveInventorySchemaVersion = "cloudring.kubeadm.ha-wave-inventory/v2"

	HAWavePhaseOneToTwo   = "one-to-two"
	HAWavePhaseTwoToThree = "two-to-three"

	maximumHAWaveEvidenceAge = 24 * time.Hour
	maximumHAWaveFutureSkew  = 5 * time.Minute
)

const (
	haWavePlanNonClaim   = "read-only phase plan; no kubeadm, etcd, node, workload, DNS, certificate, GitOps, backup, or provider mutation was attempted"
	haWaveVerifyNonClaim = "read-only phase verification; observation does not perform or authorize kubeadm, etcd, node, workload, DNS, certificate, GitOps, backup, or provider mutation"
)

var (
	haWaveSteps = []string{
		"preserve the existing live endpoint and workloads",
		"promote exactly one member for this phase",
		"verify the target control-plane, etcd, and API-server counts before continuing",
		"stop after this phase; take and validate a new off-cell backup before any next phase",
	}
	haWaveRollback = []string{
		"stop before another member change",
		"remove only the newly introduced member identified by the verification receipt using the recorded kubeadm and etcd rollback procedure",
		"verify the original live member set and workloads before retrying",
	}
)

// HAWaveCounts is the sanitized healthy-member topology used by the wave
// planner and verifier.
type HAWaveCounts struct {
	ControlPlane int `json:"controlPlane"`
	Etcd         int `json:"etcd"`
	APIServer    int `json:"apiServer"`
}

// HAWaveMemberIdentity carries only the hashed identity and healthy roles
// needed to derive wave topology. It intentionally omits names and addresses.
type HAWaveMemberIdentity struct {
	UIDSHA256    string `json:"uidSha256"`
	Ready        bool   `json:"ready"`
	ControlPlane bool   `json:"controlPlane"`
	EtcdMember   bool   `json:"etcdMember"`
}

// HAWaveInventoryReceipt is a sanitized, identity-bound preflight receipt.
// Counts are derived from its Ready node identities and API-server identity
// set; callers cannot supply counts separately to VerifyHAWave. Every Node UID
// hash must use kubeidentity.NodeUIDSHA256 and declare its algorithm identifier.
type HAWaveInventoryReceipt struct {
	SchemaVersion               string                      `json:"schemaVersion"`
	CapturedAt                  string                      `json:"capturedAt"`
	InstallationID              string                      `json:"installationId"`
	Distribution                string                      `json:"distribution"`
	Bootstrap                   string                      `json:"bootstrap"`
	ServerVersion               string                      `json:"serverVersion"`
	NodeUIDHashAlgorithm        string                      `json:"nodeUidHashAlgorithm"`
	Members                     []HAWaveMemberIdentity      `json:"members"`
	APIServerNodeUIDSHA256      []string                    `json:"apiServerNodeUidSha256"`
	OneServerLossReceiptBinding OneServerLossReceiptBinding `json:"oneServerLossReceiptBinding"`
	ReceiptSHA256               string                      `json:"receiptSha256"`
}

// HAWaveCheck is a source-safe evidence summary. Artifact contains only a
// basename; private paths and evidence payloads are never copied into reports.
type HAWaveCheck struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Artifact string `json:"artifact,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Detail   string `json:"detail"`
}

// HAWaveBackupValidator validates a deployment-owned off-cell backup and
// restore barrier. It returns its generation time and exact artifact SHA-256.
// The public planner independently enforces freshness and wave ordering.
type HAWaveBackupValidator func(path, installationID string, now time.Time) (generatedAt time.Time, artifactSHA256 string, err error)

// HAWaveOneServerLossLoader loads a protected public one-server-loss receipt
// without exposing its private path or contents in the verification report.
// VerifyHAWave independently validates the receipt, topology, and freshness.
type HAWaveOneServerLossLoader func(path string, now time.Time) (receipt *oneserverloss.Receipt, artifactSHA256 string, err error)

// HAWaveInventoryLoader loads one protected, sanitized preflight receipt.
// BuildHAWavePlan and VerifyHAWave independently validate its self-digest,
// identities, runtime policy, freshness, and installation binding.
type HAWaveInventoryLoader func(path string, now time.Time) (receipt *HAWaveInventoryReceipt, artifactSHA256 string, err error)

type HAWavePlanOptions struct {
	InstallationID string
	// Current is retained for caller compatibility and, when non-zero, must
	// match the topology derived from PreflightInventoryPath.
	Current                HAWaveCounts
	PreflightInventoryPath string
	LoadPreflightInventory HAWaveInventoryLoader
	BackupBarrierPath      string
	PreviousWavePath       string
	Now                    func() time.Time
	ValidateBackup         HAWaveBackupValidator
}

// HAWavePlan is a read-only, one-member expansion plan. MutationAllowed is
// always false; deployment-specific code owns any separately approved apply.
type HAWavePlan struct {
	SchemaVersion                   string        `json:"schemaVersion"`
	GeneratedAt                     string        `json:"generatedAt"`
	Status                          string        `json:"status"`
	Phase                           string        `json:"phase,omitempty"`
	InstallationID                  string        `json:"installationId"`
	From                            HAWaveCounts  `json:"from"`
	Target                          HAWaveCounts  `json:"target"`
	PreflightInventoryReceiptSHA256 string        `json:"preflightInventoryReceiptSha256"`
	PreflightCapturedAt             string        `json:"preflightCapturedAt"`
	NodeUIDHashAlgorithm            string        `json:"nodeUidHashAlgorithm"`
	StartingMemberUIDSHA256         []string      `json:"startingMemberUidSha256"`
	StartingMemberSetSHA256         string        `json:"startingMemberSetSha256"`
	BackupGeneratedAt               string        `json:"backupGeneratedAt,omitempty"`
	Checks                          []HAWaveCheck `json:"checks"`
	Blockers                        []string      `json:"blockers"`
	Steps                           []string      `json:"steps,omitempty"`
	Rollback                        []string      `json:"rollback,omitempty"`
	MutationAllowed                 bool          `json:"mutationAllowed"`
	NonClaim                        string        `json:"nonClaim"`
}

type HAWaveVerifyOptions struct {
	PlanPath                 string
	BackupBarrierPath        string
	ValidateBackup           HAWaveBackupValidator
	InventoryPath            string
	LoadInventory            HAWaveInventoryLoader
	FinalOneServerLossPath   string
	Now                      func() time.Time
	LoadOneServerLossReceipt HAWaveOneServerLossLoader
}

// HAWaveVerification is the sanitized read-only result for one completed
// expansion phase.
type HAWaveVerification struct {
	SchemaVersion                   string        `json:"schemaVersion"`
	GeneratedAt                     string        `json:"generatedAt"`
	CompletedAt                     string        `json:"completedAt"`
	Status                          string        `json:"status"`
	Phase                           string        `json:"phase,omitempty"`
	InstallationID                  string        `json:"installationId,omitempty"`
	PlanSHA256                      string        `json:"planSha256,omitempty"`
	InventoryReceiptSHA256          string        `json:"inventoryReceiptSha256,omitempty"`
	OneServerLossReceiptSHA256      string        `json:"oneServerLossReceiptSha256,omitempty"`
	PreflightInventoryReceiptSHA256 string        `json:"preflightInventoryReceiptSha256,omitempty"`
	NodeUIDHashAlgorithm            string        `json:"nodeUidHashAlgorithm,omitempty"`
	StartingMemberUIDSHA256         []string      `json:"startingMemberUidSha256"`
	StartingMemberSetSHA256         string        `json:"startingMemberSetSha256,omitempty"`
	FinalMemberUIDSHA256            []string      `json:"finalMemberUidSha256"`
	FinalMemberSetSHA256            string        `json:"finalMemberSetSha256,omitempty"`
	IntroducedMemberUIDSHA256       string        `json:"introducedMemberUidSha256,omitempty"`
	Observed                        HAWaveCounts  `json:"observed"`
	FreshBackupVerified             bool          `json:"freshBackupVerified"`
	PreviousWaveVerified            bool          `json:"previousWaveVerified"`
	FinalOneServerLossVerified      bool          `json:"finalOneServerLossVerified"`
	Checks                          []HAWaveCheck `json:"checks"`
	Blockers                        []string      `json:"blockers"`
	MutationAttempted               bool          `json:"mutationAttempted"`
	NonClaim                        string        `json:"nonClaim"`
}

// BuildHAWavePlan builds a read-only 1->2 or 2->3 kubeadm HA expansion plan.
// A fresh preflight inventory and off-cell backup are required for every wave;
// 2->3 additionally requires a ready 1->2 verification, a backup newer than
// its completion, and a preflight captured strictly after both.
func BuildHAWavePlan(opts HAWavePlanOptions) HAWavePlan {
	now := haWaveNow(opts.Now)
	plan := HAWavePlan{
		SchemaVersion:           HAWaveSchemaVersion,
		GeneratedAt:             formatHAWaveTime(now),
		Status:                  "blocked",
		InstallationID:          strings.TrimSpace(opts.InstallationID),
		StartingMemberUIDSHA256: []string{},
		Checks:                  []HAWaveCheck{},
		Blockers:                []string{},
		MutationAllowed:         false,
		NonClaim:                haWavePlanNonClaim,
	}
	if now.IsZero() {
		plan.block("ha_wave_clock_invalid", "clock", "a non-zero UTC planning time is required", "", "")
	}
	if !validDNS1123Subdomain(plan.InstallationID) {
		plan.block("ha_wave_installation_id_invalid", "installation_id", "a source-safe DNS-1123 installation id is required", "", "")
	}
	preflightArtifact := safeHAWaveArtifact(opts.PreflightInventoryPath)
	if preflightArtifact == "" || opts.LoadPreflightInventory == nil {
		plan.block("ha_wave_preflight_inventory_invalid", "preflight_inventory", "a fresh identity-bound preflight inventory receipt is required", preflightArtifact, "")
	} else {
		preflight, artifactSHA, loadErr := opts.LoadPreflightInventory(opts.PreflightInventoryPath, now)
		if loadErr != nil || preflight == nil {
			plan.block("ha_wave_preflight_inventory_invalid", "preflight_inventory", "a fresh identity-bound preflight inventory receipt is required", preflightArtifact, "")
		} else {
			counts, validateErr := ValidateHAWaveInventoryReceipt(preflight, now)
			preflightAt, timeErr := parseHAWaveTime(preflight.CapturedAt)
			if validateErr != nil || timeErr != nil || preflightAt.After(now) ||
				!validHAWaveSHA256(artifactSHA) || preflight.InstallationID != plan.InstallationID {
				plan.block("ha_wave_preflight_inventory_invalid", "preflight_inventory", "a fresh identity-bound preflight inventory receipt is required", preflightArtifact, "")
			} else {
				plan.From = counts
				plan.PreflightInventoryReceiptSHA256 = preflight.ReceiptSHA256
				plan.PreflightCapturedAt = preflight.CapturedAt
				plan.NodeUIDHashAlgorithm = preflight.NodeUIDHashAlgorithm
				plan.StartingMemberUIDSHA256 = haWaveInventoryMemberUIDs(preflight)
				plan.StartingMemberSetSHA256 = HAWaveMemberSetSHA256(plan.StartingMemberUIDSHA256)
				plan.pass("preflight_inventory", "starting control-plane and etcd member identities are bound by canonical SHA-256", preflightArtifact, artifactSHA)
				if opts.Current != (HAWaveCounts{}) && opts.Current != counts {
					plan.block("ha_wave_current_topology_invalid", "current_topology_binding", "caller-supplied current counts must match the identity-bound preflight inventory", "", "")
				}
			}
		}
	}
	from, phase, topologyOK := haWavePhase(plan.From)
	if !topologyOK {
		plan.block("ha_wave_current_topology_invalid", "current_topology", "current control-plane, etcd, and API-server counts must be equal and exactly 1 or 2", "", "")
	} else {
		plan.Phase = phase
		plan.Target = HAWaveCounts{ControlPlane: from + 1, Etcd: from + 1, APIServer: from + 1}
		plan.pass("current_topology", fmt.Sprintf("phase=%s members=%d", phase, from), "", "")
	}

	var backupAt time.Time
	backupArtifact := safeHAWaveArtifact(opts.BackupBarrierPath)
	if backupArtifact == "" {
		plan.block("ha_wave_backup_artifact_invalid", "fresh_backup", "a source-safe off-cell backup artifact basename is required", "", "")
	} else if opts.ValidateBackup == nil {
		plan.block("ha_wave_backup_validator_missing", "fresh_backup", "a deployment-owned off-cell backup validator is required", backupArtifact, "")
	} else {
		var backupSHA string
		var err error
		backupAt, backupSHA, err = opts.ValidateBackup(opts.BackupBarrierPath, plan.InstallationID, now)
		if err != nil || !freshHAWaveTime(backupAt, now) || !validHAWaveSHA256(backupSHA) {
			plan.block("ha_wave_backup_invalid", "fresh_backup", "a fresh off-cell backup and restore barrier is required for this wave", backupArtifact, "")
		} else {
			plan.BackupGeneratedAt = formatHAWaveTime(backupAt)
			plan.pass("fresh_backup", "fresh off-cell backup and restore barrier is valid", backupArtifact, backupSHA)
		}
	}

	switch phase {
	case HAWavePhaseTwoToThree:
		previousArtifact := safeHAWaveArtifact(opts.PreviousWavePath)
		previous, previousSHA, err := ReadHAWaveVerification(opts.PreviousWavePath)
		if previousArtifact == "" || err != nil || previous.Phase != HAWavePhaseOneToTwo || previous.InstallationID != plan.InstallationID ||
			previous.Observed != haWaveCounts(2) || previous.FinalMemberSetSHA256 != plan.StartingMemberSetSHA256 ||
			!slices.Equal(previous.FinalMemberUIDSHA256, plan.StartingMemberUIDSHA256) {
			plan.block("ha_wave_previous_verification_invalid", "previous_wave", "a ready one-to-two verification with two healthy members is required", previousArtifact, "")
		} else {
			completedAt, parseErr := parseHAWaveTime(previous.CompletedAt)
			preflightAt, preflightParseErr := parseHAWaveTime(plan.PreflightCapturedAt)
			if parseErr != nil || !backupAt.After(completedAt) {
				plan.block("ha_wave_interwave_backup_not_fresh", "previous_wave", "the two-to-three off-cell backup must be newer than completion of the one-to-two wave", previousArtifact, previousSHA)
			} else if preflightParseErr != nil || !preflightAt.After(completedAt) || !preflightAt.After(backupAt) {
				plan.block("ha_wave_interwave_preflight_not_fresh", "previous_wave", "the two-to-three preflight inventory must be newer than both the one-to-two verification and inter-wave backup", previousArtifact, previousSHA)
			} else {
				plan.pass("previous_wave", "one-to-two verification is ready; the inter-wave backup and subsequent preflight are strictly ordered", previousArtifact, previousSHA)
			}
		}
	case HAWavePhaseOneToTwo:
		if strings.TrimSpace(opts.PreviousWavePath) != "" {
			plan.block("ha_wave_previous_verification_unexpected", "previous_wave", "one-to-two must not consume a previous-wave verification", safeHAWaveArtifact(opts.PreviousWavePath), "")
		}
	}
	if len(plan.Blockers) == 0 {
		plan.Status = "ready"
		plan.Steps = slices.Clone(haWaveSteps)
		plan.Rollback = slices.Clone(haWaveRollback)
	}
	return plan
}

// VerifyHAWave reopens one exact plan and backup barrier, then derives healthy
// member counts from an identity-bound inventory receipt. It never performs or
// authorizes a mutation. Final one-server-loss evidence is forbidden at two
// members and mandatory after the three-member target is observed.
func VerifyHAWave(opts HAWaveVerifyOptions) HAWaveVerification {
	now := haWaveNow(opts.Now)
	report := HAWaveVerification{
		SchemaVersion:     HAWaveSchemaVersion,
		GeneratedAt:       formatHAWaveTime(now),
		CompletedAt:       formatHAWaveTime(now),
		Status:            "blocked",
		Checks:            []HAWaveCheck{},
		Blockers:          []string{},
		MutationAttempted: false,
		NonClaim:          haWaveVerifyNonClaim,
	}
	if now.IsZero() {
		report.block("ha_wave_clock_invalid", "clock", "a non-zero UTC verification time is required", "", "")
		return report
	}
	planArtifact := safeHAWaveArtifact(opts.PlanPath)
	plan, planSHA, err := ReadHAWavePlan(opts.PlanPath)
	if planArtifact == "" || err != nil {
		report.block("ha_wave_plan_invalid", "plan", "a ready versioned read-only HA-wave plan is required", planArtifact, "")
		return report
	}
	report.Phase = plan.Phase
	report.InstallationID = plan.InstallationID
	report.PlanSHA256 = planSHA
	report.PreflightInventoryReceiptSHA256 = plan.PreflightInventoryReceiptSHA256
	report.NodeUIDHashAlgorithm = plan.NodeUIDHashAlgorithm
	report.StartingMemberUIDSHA256 = slices.Clone(plan.StartingMemberUIDSHA256)
	report.StartingMemberSetSHA256 = plan.StartingMemberSetSHA256
	report.PreviousWaveVerified = plan.Phase == HAWavePhaseOneToTwo || hasPassingHAWaveCheck(plan.Checks, "previous_wave")
	report.pass("plan", "ready HA-wave plan is bound by SHA-256", planArtifact, planSHA)
	planGeneratedAt, planGeneratedTimeErr := parseHAWaveTime(plan.GeneratedAt)
	planBackupAt, planBackupTimeErr := parseHAWaveTime(plan.BackupGeneratedAt)
	if planGeneratedTimeErr != nil || planBackupTimeErr != nil || planGeneratedAt.After(now) || planBackupAt.After(now) {
		report.block("ha_wave_plan_invalid", "plan", "a ready versioned read-only HA-wave plan is required", planArtifact, "")
		return report
	}

	plannedBackup, plannedBackupOK := findHAWaveCheck(plan.Checks, "fresh_backup")
	backupArtifact := safeHAWaveArtifact(opts.BackupBarrierPath)
	if !plannedBackupOK || opts.ValidateBackup == nil || backupArtifact == "" {
		report.block("ha_wave_backup_revalidation_invalid", "fresh_backup", "verification must reopen the exact fresh off-cell backup and restore barrier bound by the plan", backupArtifact, "")
	} else {
		backupAt, backupSHA, backupErr := opts.ValidateBackup(opts.BackupBarrierPath, plan.InstallationID, now)
		if backupErr != nil || !freshHAWaveTime(backupAt, now) || formatHAWaveTime(backupAt) != plan.BackupGeneratedAt ||
			backupSHA != plannedBackup.SHA256 || backupArtifact != plannedBackup.Artifact {
			report.block("ha_wave_backup_revalidation_invalid", "fresh_backup", "verification must reopen the exact fresh off-cell backup and restore barrier bound by the plan", backupArtifact, "")
		} else {
			report.FreshBackupVerified = true
			report.pass("fresh_backup", "exact planned off-cell backup and restore barrier was reopened and remains fresh", plannedBackup.Artifact, backupSHA)
		}
	}

	var inventory *HAWaveInventoryReceipt
	var inventoryCapturedAt time.Time
	inventoryArtifact := safeHAWaveArtifact(opts.InventoryPath)
	if opts.LoadInventory == nil || inventoryArtifact == "" {
		report.block("ha_wave_inventory_receipt_invalid", "inventory", "a fresh identity-bound kubeadm inventory receipt is required; manual counts are not accepted", inventoryArtifact, "")
	} else {
		var inventorySHA string
		var inventoryErr error
		inventory, inventorySHA, inventoryErr = opts.LoadInventory(opts.InventoryPath, now)
		counts, validateErr := ValidateHAWaveInventoryReceipt(inventory, now)
		if inventory != nil {
			inventoryCapturedAt, _ = parseHAWaveTime(inventory.CapturedAt)
		}
		if inventoryErr != nil || inventory == nil || validateErr != nil || !validHAWaveSHA256(inventorySHA) || inventory.InstallationID != plan.InstallationID ||
			inventory.NodeUIDHashAlgorithm != plan.NodeUIDHashAlgorithm || !inventoryCapturedAt.After(planGeneratedAt) ||
			!inventoryCapturedAt.After(planBackupAt) || inventoryCapturedAt.After(now) {
			report.block("ha_wave_inventory_receipt_invalid", "inventory", "a fresh identity-bound kubeadm inventory receipt is required; manual counts are not accepted", inventoryArtifact, "")
			inventory = nil
		} else {
			report.Observed = counts
			report.InventoryReceiptSHA256 = inventory.ReceiptSHA256
			report.FinalMemberUIDSHA256 = haWaveInventoryMemberUIDs(inventory)
			report.FinalMemberSetSHA256 = HAWaveMemberSetSHA256(report.FinalMemberUIDSHA256)
			report.pass("inventory", "healthy member counts were derived from an identity-bound kubeadm inventory receipt", inventoryArtifact, inventorySHA)
		}
	}
	introducedMember, transitionErr := validateHAWaveMemberTransition(report.StartingMemberUIDSHA256, report.FinalMemberUIDSHA256)
	if transitionErr != nil {
		report.block("ha_wave_member_identity_transition_invalid", "member_identity_transition", "final members must equal the exact starting set plus one unique introduced identity", "", "")
	} else {
		report.IntroducedMemberUIDSHA256 = introducedMember
		report.pass("member_identity_transition", "exactly one introduced member identity was added without replacement or deletion", "", "")
	}
	if report.Observed != plan.Target {
		report.block("ha_wave_target_topology_not_observed", "target_topology", fmt.Sprintf("observed topology must exactly match target controlPlane=%d etcd=%d apiServer=%d", plan.Target.ControlPlane, plan.Target.Etcd, plan.Target.APIServer), "", "")
	} else {
		report.pass("target_topology", fmt.Sprintf("observed healthy members=%d", plan.Target.ControlPlane), "", "")
	}

	if plan.Target == haWaveCounts(3) {
		artifact := safeHAWaveArtifact(opts.FinalOneServerLossPath)
		if artifact == "" || opts.LoadOneServerLossReceipt == nil {
			report.block("ha_wave_final_one_server_loss_invalid", "final_one_server_loss", "a fresh final one-server-loss receipt bound to the recovered three-member topology is required", artifact, "")
		} else {
			receipt, artifactSHA, loadErr := opts.LoadOneServerLossReceipt(opts.FinalOneServerLossPath, now)
			if loadErr != nil || !validHAWaveSHA256(artifactSHA) ||
				validateHAWaveOneServerLossReceipt(receipt, inventory, plan.Target, now, planGeneratedAt, planBackupAt) != nil {
				report.block("ha_wave_final_one_server_loss_invalid", "final_one_server_loss", "a fresh final one-server-loss receipt bound to the recovered three-member topology is required", artifact, "")
			} else {
				report.FinalOneServerLossVerified = true
				report.OneServerLossReceiptSHA256 = receipt.ReceiptSHA256
				report.pass("final_one_server_loss", "final one-server-loss receipt is valid after three members were observed", artifact, artifactSHA)
			}
		}
	} else {
		if inventory != nil && inventory.OneServerLossReceiptBinding != (OneServerLossReceiptBinding{}) {
			report.block("ha_wave_final_one_server_loss_too_early", "final_one_server_loss", "final one-server-loss evidence is forbidden before the three-member phase", safeHAWaveArtifact(opts.InventoryPath), "")
		}
		if strings.TrimSpace(opts.FinalOneServerLossPath) != "" {
			report.block("ha_wave_final_one_server_loss_too_early", "final_one_server_loss", "final one-server-loss evidence is forbidden before the three-member phase", safeHAWaveArtifact(opts.FinalOneServerLossPath), "")
		}
	}
	if len(report.Blockers) == 0 {
		report.Status = "ready"
	}
	return report
}

// ReadHAWavePlan strictly reads and validates one ready, read-only plan.
func ReadHAWavePlan(path string) (HAWavePlan, string, error) {
	var plan HAWavePlan
	sha, err := readHAWaveJSON(path, &plan)
	if err != nil || validateReadyHAWavePlan(plan) != nil {
		return HAWavePlan{}, "", errors.New("HA-wave plan is invalid")
	}
	return plan, sha, nil
}

// ReadHAWaveVerification strictly reads and validates one ready, read-only
// wave verification.
func ReadHAWaveVerification(path string) (HAWaveVerification, string, error) {
	var report HAWaveVerification
	sha, err := readHAWaveJSON(path, &report)
	if err != nil || validateReadyHAWaveVerification(report) != nil {
		return HAWaveVerification{}, "", errors.New("HA-wave verification is invalid")
	}
	return report, sha, nil
}

// ValidateHAWaveInventoryReceipt validates one sanitized preflight receipt and
// derives healthy control-plane, etcd, and API-server counts from its bound
// member identity sets.
func ValidateHAWaveInventoryReceipt(receipt *HAWaveInventoryReceipt, now time.Time) (HAWaveCounts, error) {
	if receipt == nil || now.IsZero() || receipt.SchemaVersion != HAWaveInventorySchemaVersion ||
		!validDNS1123Subdomain(receipt.InstallationID) || receipt.Distribution != "upstream" || receipt.Bootstrap != "kubeadm" ||
		receipt.NodeUIDHashAlgorithm != kubeidentity.NodeUIDHashAlgorithm ||
		!kubernetesVersionPattern.MatchString(receipt.ServerVersion) || strings.Contains(strings.ToLower(receipt.ServerVersion), "+k3s") ||
		!validHAWaveSHA256(receipt.ReceiptSHA256) || receipt.ReceiptSHA256 != HAWaveInventoryReceiptSHA256(*receipt) {
		return HAWaveCounts{}, errors.New("HA-wave inventory receipt is invalid")
	}
	capturedAt, err := parseHAWaveTime(receipt.CapturedAt)
	if err != nil || !freshHAWaveTime(capturedAt, now) || len(receipt.Members) < 1 || len(receipt.Members) > 3 ||
		len(receipt.APIServerNodeUIDSHA256) != len(receipt.Members) {
		return HAWaveCounts{}, errors.New("HA-wave inventory receipt topology is invalid")
	}
	memberUIDs := make(map[string]struct{}, len(receipt.Members))
	previousUID := ""
	counts := HAWaveCounts{}
	for _, member := range receipt.Members {
		if !validHAWaveSHA256(member.UIDSHA256) || member.UIDSHA256 <= previousUID || !member.Ready || !member.ControlPlane || !member.EtcdMember {
			return HAWaveCounts{}, errors.New("HA-wave inventory member identity is invalid")
		}
		memberUIDs[member.UIDSHA256] = struct{}{}
		previousUID = member.UIDSHA256
		counts.ControlPlane++
		counts.Etcd++
	}
	previousUID = ""
	for _, uid := range receipt.APIServerNodeUIDSHA256 {
		if !validHAWaveSHA256(uid) || uid <= previousUID {
			return HAWaveCounts{}, errors.New("HA-wave API-server identity set is invalid")
		}
		if _, exists := memberUIDs[uid]; !exists {
			return HAWaveCounts{}, errors.New("HA-wave API-server identity is not a captured member")
		}
		previousUID = uid
		counts.APIServer++
	}
	return counts, nil
}

// HAWaveInventoryReceiptSHA256 returns the canonical self-digest for a
// sanitized inventory receipt with ReceiptSHA256 excluded.
func HAWaveInventoryReceiptSHA256(receipt HAWaveInventoryReceipt) string {
	receipt.ReceiptSHA256 = ""
	payload, err := json.Marshal(receipt)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// HAWaveMemberSetSHA256 returns a deterministic, order-independent digest for
// one privacy-safe set of unique member UID hashes. Malformed or duplicate
// identities are rejected with an empty digest.
func HAWaveMemberSetSHA256(memberUIDSHA256 []string) string {
	canonical, err := canonicalHAWaveMemberUIDs(memberUIDSHA256)
	if err != nil {
		return ""
	}
	return oneserverloss.ControlPlaneMemberSetSHA256(canonical)
}

func validateReadyHAWavePlan(plan HAWavePlan) error {
	from, phase, ok := haWavePhase(plan.From)
	canonicalStart, startErr := canonicalHAWaveMemberUIDs(plan.StartingMemberUIDSHA256)
	preflightAt, preflightTimeErr := parseHAWaveTime(plan.PreflightCapturedAt)
	generatedAt, generatedTimeErr := parseHAWaveTime(plan.GeneratedAt)
	backupAt, backupTimeErr := parseHAWaveTime(plan.BackupGeneratedAt)
	if !ok || plan.SchemaVersion != HAWaveSchemaVersion || plan.Status != "ready" || plan.Phase != phase ||
		plan.Target != haWaveCounts(from+1) || !validDNS1123Subdomain(plan.InstallationID) || plan.MutationAllowed ||
		startErr != nil || len(canonicalStart) != from || !slices.Equal(canonicalStart, plan.StartingMemberUIDSHA256) ||
		preflightTimeErr != nil || generatedTimeErr != nil || preflightAt.After(generatedAt) ||
		backupTimeErr != nil || phase == HAWavePhaseTwoToThree && !preflightAt.After(backupAt) ||
		plan.NodeUIDHashAlgorithm != kubeidentity.NodeUIDHashAlgorithm ||
		!validHAWaveSHA256(plan.PreflightInventoryReceiptSHA256) || !validHAWaveSHA256(plan.StartingMemberSetSHA256) ||
		plan.StartingMemberSetSHA256 != HAWaveMemberSetSHA256(plan.StartingMemberUIDSHA256) ||
		len(plan.Blockers) != 0 || plan.NonClaim != haWavePlanNonClaim || !slices.Equal(plan.Steps, haWaveSteps) ||
		!slices.Equal(plan.Rollback, haWaveRollback) || !canonicalHAWaveTime(plan.GeneratedAt) || !canonicalHAWaveTime(plan.BackupGeneratedAt) ||
		!hasExactHAWavePlanChecks(plan.Checks, phase == HAWavePhaseTwoToThree) {
		return errors.New("HA-wave plan contract is not ready and read-only")
	}
	return nil
}

func validateReadyHAWaveVerification(report HAWaveVerification) error {
	want := HAWaveCounts{}
	finalRequired := false
	switch report.Phase {
	case HAWavePhaseOneToTwo:
		want = haWaveCounts(2)
	case HAWavePhaseTwoToThree:
		want = haWaveCounts(3)
		finalRequired = true
	default:
		return errors.New("HA-wave verification phase is invalid")
	}
	introduced, transitionErr := validateHAWaveMemberTransition(report.StartingMemberUIDSHA256, report.FinalMemberUIDSHA256)
	if report.SchemaVersion != HAWaveSchemaVersion || report.Status != "ready" || !validDNS1123Subdomain(report.InstallationID) ||
		report.Observed != want || !report.FreshBackupVerified || !report.PreviousWaveVerified ||
		report.NodeUIDHashAlgorithm != kubeidentity.NodeUIDHashAlgorithm ||
		report.FinalOneServerLossVerified != finalRequired || !validHAWaveSHA256(report.PlanSHA256) || report.MutationAttempted ||
		transitionErr != nil || introduced != report.IntroducedMemberUIDSHA256 || len(report.FinalMemberUIDSHA256) != want.ControlPlane ||
		!validHAWaveSHA256(report.PreflightInventoryReceiptSHA256) ||
		report.StartingMemberSetSHA256 != HAWaveMemberSetSHA256(report.StartingMemberUIDSHA256) ||
		report.FinalMemberSetSHA256 != HAWaveMemberSetSHA256(report.FinalMemberUIDSHA256) ||
		!validHAWaveSHA256(report.InventoryReceiptSHA256) || finalRequired && !validHAWaveSHA256(report.OneServerLossReceiptSHA256) ||
		!finalRequired && report.OneServerLossReceiptSHA256 != "" ||
		len(report.Blockers) != 0 || report.NonClaim != haWaveVerifyNonClaim || !canonicalHAWaveTime(report.GeneratedAt) ||
		!canonicalHAWaveTime(report.CompletedAt) || report.GeneratedAt != report.CompletedAt ||
		!hasExactHAWaveVerificationChecks(report.Checks, finalRequired) {
		return errors.New("HA-wave verification contract is not ready and read-only")
	}
	return nil
}

func validateHAWaveOneServerLossReceipt(
	receipt *oneserverloss.Receipt,
	inventory *HAWaveInventoryReceipt,
	target HAWaveCounts,
	now, planGeneratedAt, backupGeneratedAt time.Time,
) error {
	if err := oneserverloss.ValidateReceipt(receipt); err != nil {
		return errors.New("one-server-loss receipt failed offline validation")
	}
	if receipt.Baseline.ControlPlaneNodes != target.ControlPlane || receipt.Baseline.EtcdMembers != target.Etcd ||
		receipt.Baseline.APIServerMembers != target.APIServer || receipt.MinimumControlPlane < 3 || inventory == nil {
		return errors.New("one-server-loss baseline does not match target topology")
	}
	binding := inventory.OneServerLossReceiptBinding
	memberSetSHA256 := HAWaveMemberSetSHA256(haWaveInventoryMemberUIDs(inventory))
	if binding.ReceiptSHA256 != receipt.ReceiptSHA256 || binding.RunNonceSHA256 != receipt.RunNonceSHA256 ||
		binding.TargetNodeUIDSHA256 != receipt.TargetNodeUIDSHA256 || binding.KubectlExecutableSHA256 != receipt.KubectlExecutableSHA256 ||
		binding.ProbeAdapterSHA256 != receipt.ProbeAdapterSHA256 || !validHAWaveSHA256(memberSetSHA256) ||
		inventory.NodeUIDHashAlgorithm != kubeidentity.NodeUIDHashAlgorithm || receipt.NodeUIDHashAlgorithm != kubeidentity.NodeUIDHashAlgorithm ||
		binding.NodeUIDHashAlgorithm != kubeidentity.NodeUIDHashAlgorithm ||
		binding.ControlPlaneMemberSetSHA256 != memberSetSHA256 || receipt.Baseline.ControlPlaneMemberSetSHA256 != memberSetSHA256 ||
		!haWaveInventoryHasMember(inventory, receipt.TargetNodeUIDSHA256) {
		return errors.New("one-server-loss receipt is not identity-bound to the inventory")
	}
	completedAt, completedTimeErr := parseHAWaveTime(receipt.CompletedAt)
	inventoryCapturedAt, inventoryTimeErr := parseHAWaveTime(inventory.CapturedAt)
	if completedTimeErr != nil || inventoryTimeErr != nil || !freshHAWaveTime(completedAt, now) ||
		completedAt.After(now) || inventoryCapturedAt.After(now) ||
		!completedAt.After(planGeneratedAt) || !completedAt.After(backupGeneratedAt) ||
		!inventoryCapturedAt.After(completedAt) {
		return errors.New("one-server-loss receipt is stale or future-dated")
	}
	return nil
}

func readHAWaveJSON(path string, destination any) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("HA-wave evidence path is required")
	}
	// #nosec G304 G703 -- the local operator explicitly selects a bounded,
	// strict, sanitized HA-wave evidence input.
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", errors.New("HA-wave evidence is unavailable")
	}
	defer file.Close()
	payload, err := strictjson.Read(file)
	if err != nil {
		return "", errors.New("HA-wave evidence JSON is invalid")
	}
	if err := strictjson.DecodeExact(payload, destination); err != nil {
		return "", errors.New("HA-wave evidence JSON is invalid")
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func haWaveNow(clock func() time.Time) time.Time {
	if clock == nil {
		return time.Now().UTC()
	}
	now := clock()
	if now.IsZero() {
		return time.Time{}
	}
	return now.UTC()
}

func haWavePhase(current HAWaveCounts) (int, string, bool) {
	if current.ControlPlane != current.Etcd || current.ControlPlane != current.APIServer {
		return 0, "", false
	}
	switch current.ControlPlane {
	case 1:
		return 1, HAWavePhaseOneToTwo, true
	case 2:
		return 2, HAWavePhaseTwoToThree, true
	default:
		return 0, "", false
	}
}

func haWaveCounts(value int) HAWaveCounts {
	return HAWaveCounts{ControlPlane: value, Etcd: value, APIServer: value}
}

func formatHAWaveTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func parseHAWaveTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("HA-wave timestamp is invalid")
	}
	return parsed, nil
}

func canonicalHAWaveTime(value string) bool {
	_, err := parseHAWaveTime(value)
	return err == nil
}

func freshHAWaveTime(value, now time.Time) bool {
	if value.IsZero() || now.IsZero() {
		return false
	}
	value, now = value.UTC(), now.UTC()
	return !value.Before(now.Add(-maximumHAWaveEvidenceAge)) && !value.After(now.Add(maximumHAWaveFutureSkew))
}

func safeHAWaveArtifact(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	base := filepath.Base(filepath.Clean(trimmed))
	if base == "." || base == string(filepath.Separator) || len(base) > 128 {
		return ""
	}
	for index, value := range base {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' ||
			index > 0 && (value == '.' || value == '_' || value == '-') {
			continue
		}
		return ""
	}
	return base
}

func validHAWaveSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func hasPassingHAWaveCheck(checks []HAWaveCheck, id string) bool {
	for _, check := range checks {
		if check.ID == id && check.Status == "pass" && validHAWaveSHA256(check.SHA256) {
			return true
		}
	}
	return false
}

func findHAWaveCheck(checks []HAWaveCheck, id string) (HAWaveCheck, bool) {
	for _, check := range checks {
		if check.ID == id {
			return check, true
		}
	}
	return HAWaveCheck{}, false
}

func haWaveInventoryHasMember(inventory *HAWaveInventoryReceipt, uid string) bool {
	if inventory == nil {
		return false
	}
	for _, member := range inventory.Members {
		if member.UIDSHA256 == uid {
			return true
		}
	}
	return false
}

func haWaveInventoryMemberUIDs(inventory *HAWaveInventoryReceipt) []string {
	if inventory == nil {
		return nil
	}
	uids := make([]string, 0, len(inventory.Members))
	for _, member := range inventory.Members {
		uids = append(uids, member.UIDSHA256)
	}
	return uids
}

func mapHAWaveMemberUIDs(memberUIDs map[string]struct{}) []string {
	uids := make([]string, 0, len(memberUIDs))
	for uid := range memberUIDs {
		uids = append(uids, uid)
	}
	return uids
}

func canonicalHAWaveMemberUIDs(memberUIDSHA256 []string) ([]string, error) {
	if len(memberUIDSHA256) < 1 || len(memberUIDSHA256) > 3 {
		return nil, errors.New("HA-wave member identity set size is invalid")
	}
	canonical := slices.Clone(memberUIDSHA256)
	slices.Sort(canonical)
	for index, uid := range canonical {
		if !validHAWaveSHA256(uid) || index > 0 && uid == canonical[index-1] {
			return nil, errors.New("HA-wave member identity set is invalid")
		}
	}
	return canonical, nil
}

func validateHAWaveMemberTransition(starting, final []string) (string, error) {
	canonicalStart, err := canonicalHAWaveMemberUIDs(starting)
	if err != nil || !slices.Equal(canonicalStart, starting) {
		return "", errors.New("HA-wave starting member identity set is invalid")
	}
	canonicalFinal, err := canonicalHAWaveMemberUIDs(final)
	if err != nil || !slices.Equal(canonicalFinal, final) || len(final) != len(starting)+1 {
		return "", errors.New("HA-wave final member identity set is invalid")
	}
	startingSet := make(map[string]struct{}, len(starting))
	for _, uid := range starting {
		startingSet[uid] = struct{}{}
	}
	introduced := ""
	for _, uid := range final {
		if _, existed := startingSet[uid]; existed {
			delete(startingSet, uid)
			continue
		}
		if introduced != "" {
			return "", errors.New("HA-wave final member identity set contains multiple additions")
		}
		introduced = uid
	}
	if len(startingSet) != 0 || introduced == "" {
		return "", errors.New("HA-wave final member identity set replaced or deleted a starting member")
	}
	return introduced, nil
}

func hasExactHAWavePlanChecks(checks []HAWaveCheck, previous bool) bool {
	ids := []string{"preflight_inventory", "current_topology", "fresh_backup"}
	if previous {
		ids = append(ids, "previous_wave")
	}
	return hasOrderedHAWaveChecks(checks, ids)
}

func hasExactHAWaveVerificationChecks(checks []HAWaveCheck, final bool) bool {
	ids := []string{"plan", "fresh_backup", "inventory", "member_identity_transition", "target_topology"}
	if final {
		ids = append(ids, "final_one_server_loss")
	}
	return hasOrderedHAWaveChecks(checks, ids)
}

func hasOrderedHAWaveChecks(checks []HAWaveCheck, ids []string) bool {
	if len(checks) != len(ids) {
		return false
	}
	for index, check := range checks {
		if check.ID != ids[index] || check.Status != "pass" || strings.TrimSpace(check.Detail) == "" ||
			check.Artifact != safeHAWaveArtifact(check.Artifact) {
			return false
		}
		switch check.ID {
		case "current_topology", "member_identity_transition", "target_topology":
			if check.Artifact != "" || check.SHA256 != "" {
				return false
			}
		default:
			if check.Artifact == "" || !validHAWaveSHA256(check.SHA256) {
				return false
			}
		}
	}
	return true
}

func (plan *HAWavePlan) pass(id, detail, artifact, sha string) {
	plan.Checks = append(plan.Checks, HAWaveCheck{ID: id, Status: "pass", Detail: detail, Artifact: artifact, SHA256: sha})
}

func (plan *HAWavePlan) block(blocker, id, detail, artifact, sha string) {
	plan.Checks = append(plan.Checks, HAWaveCheck{ID: id, Status: "blocked", Detail: detail, Artifact: artifact, SHA256: sha})
	plan.Blockers = appendUniqueHAWaveBlocker(plan.Blockers, blocker)
}

func (report *HAWaveVerification) pass(id, detail, artifact, sha string) {
	report.Checks = append(report.Checks, HAWaveCheck{ID: id, Status: "pass", Detail: detail, Artifact: artifact, SHA256: sha})
}

func (report *HAWaveVerification) block(blocker, id, detail, artifact, sha string) {
	report.Checks = append(report.Checks, HAWaveCheck{ID: id, Status: "blocked", Detail: detail, Artifact: artifact, SHA256: sha})
	report.Blockers = appendUniqueHAWaveBlocker(report.Blockers, blocker)
}

func appendUniqueHAWaveBlocker(values []string, value string) []string {
	if slices.Contains(values, value) {
		return values
	}
	return append(values, value)
}
