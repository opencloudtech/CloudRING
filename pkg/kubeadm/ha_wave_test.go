// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package kubeadm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/kubeidentity"
	"github.com/opencloudtech/CloudRING/pkg/resilience/oneserverloss"
)

func TestHAWaveSequencesOneToTwoThenFreshBackupThenTwoToThree(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	first := BuildHAWavePlan(withHAWavePreflight(HAWavePlanOptions{
		InstallationID:    "synthetic-cell-001",
		Current:           haWaveCounts(1),
		BackupBarrierPath: filepath.Join("private", "backup-wave-1.json"),
		Now:               fixedHAWaveClock(base),
		ValidateBackup:    passingHAWaveBackup(base.Add(-time.Minute), "backup-1"),
	}, base, 1))
	if first.Status != "ready" || first.Phase != HAWavePhaseOneToTwo || first.Target != haWaveCounts(2) || first.MutationAllowed {
		t.Fatalf("unexpected first plan: %+v", first)
	}
	if got := first.Checks[2].Artifact; got != "backup-wave-1.json" {
		t.Fatalf("private backup path was not sanitized: %q", got)
	}
	firstPlanPath := writeHAWaveJSON(t, "first-plan.json", first)
	firstVerification := VerifyHAWave(haWaveVerifyOptions(t, firstPlanPath, "backup-wave-1.json", base.Add(time.Minute), 2, nil))
	if firstVerification.Status != "ready" || firstVerification.FinalOneServerLossVerified || firstVerification.MutationAttempted {
		t.Fatalf("unexpected first verification: %+v", firstVerification)
	}
	firstVerificationPath := writeHAWaveJSON(t, "first-verification.json", firstVerification)

	second := BuildHAWavePlan(withHAWavePreflight(HAWavePlanOptions{
		InstallationID:    "synthetic-cell-001",
		Current:           haWaveCounts(2),
		BackupBarrierPath: "backup-wave-2.json",
		PreviousWavePath:  firstVerificationPath,
		Now:               fixedHAWaveClock(base.Add(3 * time.Minute)),
		ValidateBackup:    passingHAWaveBackup(base.Add(2*time.Minute), "backup-2"),
	}, base.Add(3*time.Minute), 2))
	if second.Status != "ready" || second.Phase != HAWavePhaseTwoToThree || second.Target != haWaveCounts(3) ||
		!hasPassingHAWaveCheck(second.Checks, "previous_wave") {
		t.Fatalf("unexpected second plan: %+v", second)
	}
	secondPlanPath := writeHAWaveJSON(t, "second-plan.json", second)
	receipt := testOneServerLossReceipt()
	shiftTestOneServerLossReceipt(t, &receipt, base.Add(3*time.Minute+30*time.Second))
	finalOptions := haWaveVerifyOptions(t, secondPlanPath, "backup-wave-2.json", base.Add(4*time.Minute), 3, &receipt)
	finalOptions.FinalOneServerLossPath = filepath.Join("protected", "one-server-loss.json")
	finalOptions.LoadOneServerLossReceipt = func(string, time.Time) (*oneserverloss.Receipt, string, error) {
		return &receipt, testSHA256("receipt-artifact"), nil
	}
	final := VerifyHAWave(finalOptions)
	if final.Status != "ready" || !final.FinalOneServerLossVerified || final.MutationAttempted {
		t.Fatalf("unexpected final verification: %+v", final)
	}
	if got := final.Checks[len(final.Checks)-1].Artifact; got != "one-server-loss.json" {
		t.Fatalf("private receipt path was not sanitized: %q", got)
	}
	finalPath := writeHAWaveJSON(t, "final-verification.json", final)
	if _, _, err := ReadHAWaveVerification(finalPath); err != nil {
		t.Fatalf("ready final verification did not round trip: %v", err)
	}
}

func TestHAWaveBlocksTwoToThreeWithoutNewerInterwaveBackup(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	firstPlan := BuildHAWavePlan(withHAWavePreflight(HAWavePlanOptions{
		InstallationID: "synthetic-cell-001", Current: haWaveCounts(1), BackupBarrierPath: "backup-1.json",
		Now: fixedHAWaveClock(base), ValidateBackup: passingHAWaveBackup(base.Add(-time.Minute), "backup-1"),
	}, base, 1))
	firstPlanPath := writeHAWaveJSON(t, "first-plan.json", firstPlan)
	firstVerification := VerifyHAWave(haWaveVerifyOptions(t, firstPlanPath, "backup-1.json", base.Add(time.Minute), 2, nil))
	previousPath := writeHAWaveJSON(t, "first-verification.json", firstVerification)
	second := BuildHAWavePlan(withHAWavePreflight(HAWavePlanOptions{
		InstallationID: "synthetic-cell-001", Current: haWaveCounts(2), BackupBarrierPath: "stale-backup.json",
		PreviousWavePath: previousPath, Now: fixedHAWaveClock(base.Add(2 * time.Minute)),
		ValidateBackup: passingHAWaveBackup(base.Add(30*time.Second), "stale-backup"),
	}, base.Add(2*time.Minute), 2))
	assertHAWaveBlocker(t, second.Blockers, "ha_wave_interwave_backup_not_fresh")
}

func TestHAWaveBlocksTwoToThreeWhenPreflightPredatesPriorEvidence(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	firstPlan := BuildHAWavePlan(withHAWavePreflight(HAWavePlanOptions{
		InstallationID: "synthetic-cell-001", Current: haWaveCounts(1), BackupBarrierPath: "backup-1.json",
		Now: fixedHAWaveClock(base), ValidateBackup: passingHAWaveBackup(base.Add(-time.Minute), "backup-1"),
	}, base, 1))
	firstPlanPath := writeHAWaveJSON(t, "first-plan.json", firstPlan)
	previous := VerifyHAWave(haWaveVerifyOptions(t, firstPlanPath, "backup-1.json", base.Add(time.Minute), 2, nil))
	previousPath := writeHAWaveJSON(t, "first-verification.json", previous)

	for _, test := range []struct {
		name        string
		preflightAt time.Time
	}{
		{name: "preflight before prior verification", preflightAt: base.Add(30 * time.Second)},
		{name: "preflight after verification but before inter-wave backup", preflightAt: base.Add(90 * time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			second := BuildHAWavePlan(withHAWavePreflight(HAWavePlanOptions{
				InstallationID: "synthetic-cell-001", Current: haWaveCounts(2), BackupBarrierPath: "backup-2.json",
				PreviousWavePath: previousPath, Now: fixedHAWaveClock(base.Add(3 * time.Minute)),
				ValidateBackup: passingHAWaveBackup(base.Add(2*time.Minute), "backup-2"),
			}, test.preflightAt, 2))
			assertHAWaveBlocker(t, second.Blockers, "ha_wave_interwave_preflight_not_fresh")
		})
	}
}

func TestHAWaveBlocksPreviousVerificationFromAnotherInstallation(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	firstPlan := BuildHAWavePlan(withHAWavePreflight(HAWavePlanOptions{
		InstallationID: "synthetic-cell-001", Current: haWaveCounts(1), BackupBarrierPath: "backup-1.json",
		Now: fixedHAWaveClock(base), ValidateBackup: passingHAWaveBackup(base.Add(-time.Minute), "backup-1"),
	}, base, 1))
	firstPlanPath := writeHAWaveJSON(t, "first-plan.json", firstPlan)
	previous := VerifyHAWave(haWaveVerifyOptions(t, firstPlanPath, "backup-1.json", base.Add(time.Minute), 2, nil))
	previous.InstallationID = "synthetic-cell-002"
	previousPath := writeHAWaveJSON(t, "other-cell-verification.json", previous)
	second := BuildHAWavePlan(withHAWavePreflight(HAWavePlanOptions{
		InstallationID: "synthetic-cell-001", Current: haWaveCounts(2), BackupBarrierPath: "backup-2.json",
		PreviousWavePath: previousPath, Now: fixedHAWaveClock(base.Add(3 * time.Minute)),
		ValidateBackup: passingHAWaveBackup(base.Add(2*time.Minute), "backup-2"),
	}, base.Add(3*time.Minute), 2))
	assertHAWaveBlocker(t, second.Blockers, "ha_wave_previous_verification_invalid")
}

func TestHAWaveBlocksNextPlanWhenPreflightReplacesPreviousFinalMember(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	firstPlan := BuildHAWavePlan(withHAWavePreflight(HAWavePlanOptions{
		InstallationID: "synthetic-cell-001", Current: haWaveCounts(1), BackupBarrierPath: "backup-1.json",
		Now: fixedHAWaveClock(base), ValidateBackup: passingHAWaveBackup(base.Add(-time.Minute), "backup-1"),
	}, base, 1))
	firstPlanPath := writeHAWaveJSON(t, "first-plan.json", firstPlan)
	previous := VerifyHAWave(haWaveVerifyOptions(t, firstPlanPath, "backup-1.json", base.Add(time.Minute), 2, nil))
	previousPath := writeHAWaveJSON(t, "first-verification.json", previous)

	replacedUIDs := []string{previous.FinalMemberUIDSHA256[0], testSHA256("replacement-before-second-wave")}
	slices.Sort(replacedUIDs)
	replacedPreflight := testHAWaveInventoryReceiptWithUIDs(base.Add(3*time.Minute), "synthetic-cell-001", replacedUIDs, nil)
	second := BuildHAWavePlan(HAWavePlanOptions{
		InstallationID: "synthetic-cell-001", Current: haWaveCounts(2), PreflightInventoryPath: "preflight-2.json",
		LoadPreflightInventory: func(string, time.Time) (*HAWaveInventoryReceipt, string, error) {
			return replacedPreflight, testSHA256("preflight-2-artifact"), nil
		},
		BackupBarrierPath: "backup-2.json", PreviousWavePath: previousPath, Now: fixedHAWaveClock(base.Add(3 * time.Minute)),
		ValidateBackup: passingHAWaveBackup(base.Add(2*time.Minute), "backup-2"),
	})
	assertHAWaveBlocker(t, second.Blockers, "ha_wave_previous_verification_invalid")
}

func TestHAWaveFinalOneServerLossEvidenceIsForbiddenBeforeThreeAndRequiredAfter(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	firstPlan := BuildHAWavePlan(withHAWavePreflight(HAWavePlanOptions{
		InstallationID: "synthetic-cell-001", Current: haWaveCounts(1), BackupBarrierPath: "backup-1.json",
		Now: fixedHAWaveClock(base), ValidateBackup: passingHAWaveBackup(base.Add(-time.Minute), "backup-1"),
	}, base, 1))
	firstPath := writeHAWaveJSON(t, "first-plan.json", firstPlan)
	earlyOptions := haWaveVerifyOptions(t, firstPath, "backup-1.json", base.Add(time.Minute), 2, nil)
	earlyOptions.FinalOneServerLossPath = "too-early.json"
	early := VerifyHAWave(earlyOptions)
	assertHAWaveBlocker(t, early.Blockers, "ha_wave_final_one_server_loss_too_early")

	secondPlan := readyHAWavePlanForTest(base, HAWavePhaseTwoToThree)
	secondPath := writeHAWaveJSON(t, "second-plan.json", secondPlan)
	missing := VerifyHAWave(haWaveVerifyOptions(t, secondPath, "backup.json", base, 3, nil))
	assertHAWaveBlocker(t, missing.Blockers, "ha_wave_final_one_server_loss_invalid")
}

func TestHAWaveFinalReceiptRemainsAuthoritativeAndFresh(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	planPath := writeHAWaveJSON(t, "second-plan.json", readyHAWavePlanForTest(base, HAWavePhaseTwoToThree))
	receipt := testOneServerLossReceipt()
	tests := []struct {
		name string
		now  time.Time
		load HAWaveOneServerLossLoader
	}{
		{
			name: "loader cannot replace receipt with a digest",
			now:  base,
			load: func(string, time.Time) (*oneserverloss.Receipt, string, error) {
				return nil, testSHA256("receipt-artifact"), nil
			},
		},
		{
			name: "invalid artifact digest",
			now:  base,
			load: func(string, time.Time) (*oneserverloss.Receipt, string, error) {
				return &receipt, "not-a-digest", nil
			},
		},
		{
			name: "stale valid receipt",
			now:  base.Add(maximumHAWaveEvidenceAge + time.Hour),
			load: func(string, time.Time) (*oneserverloss.Receipt, string, error) {
				return &receipt, testSHA256("receipt-artifact"), nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := haWaveVerifyOptions(t, planPath, "backup.json", test.now, 3, &receipt)
			opts.FinalOneServerLossPath = "receipt.json"
			opts.LoadOneServerLossReceipt = test.load
			report := VerifyHAWave(opts)
			assertHAWaveBlocker(t, report.Blockers, "ha_wave_final_one_server_loss_invalid")
		})
	}
}

func TestHAWaveVerificationReopensExactBackupAndRequiresInventoryReceipt(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	planPath := writeHAWaveJSON(t, "first-plan.json", readyHAWavePlanForTest(base, HAWavePhaseOneToTwo))

	missingBackup := haWaveVerifyOptions(t, planPath, "backup.json", base, 2, nil)
	missingBackup.ValidateBackup = nil
	report := VerifyHAWave(missingBackup)
	assertHAWaveBlocker(t, report.Blockers, "ha_wave_backup_revalidation_invalid")

	wrongBackup := haWaveVerifyOptions(t, planPath, "backup.json", base, 2, nil)
	wrongBackup.ValidateBackup = passingHAWaveBackup(base.Add(-time.Minute), "different-backup")
	report = VerifyHAWave(wrongBackup)
	assertHAWaveBlocker(t, report.Blockers, "ha_wave_backup_revalidation_invalid")

	missingInventory := haWaveVerifyOptions(t, planPath, "backup.json", base, 2, nil)
	missingInventory.LoadInventory = nil
	report = VerifyHAWave(missingInventory)
	assertHAWaveBlocker(t, report.Blockers, "ha_wave_inventory_receipt_invalid")
	if report.Observed != (HAWaveCounts{}) {
		t.Fatalf("counts were accepted without an inventory receipt: %+v", report.Observed)
	}

	fabricatedInventory := haWaveVerifyOptions(t, planPath, "backup.json", base, 2, nil)
	fabricatedInventory.LoadInventory = func(string, time.Time) (*HAWaveInventoryReceipt, string, error) {
		inventory := testHAWaveInventoryReceipt(base, "synthetic-cell-001", 2, nil)
		inventory.Members[0].Ready = false // ReceiptSHA256 is deliberately not recomputed.
		return inventory, testSHA256("inventory-artifact"), nil
	}
	report = VerifyHAWave(fabricatedInventory)
	assertHAWaveBlocker(t, report.Blockers, "ha_wave_inventory_receipt_invalid")
}

func TestHAWaveVerificationRequiresInventoryCapturedStrictlyAfterPlanAndBackup(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	plan := readyHAWavePlanForTest(base, HAWavePhaseOneToTwo)
	finalUIDs := append(slices.Clone(plan.StartingMemberUIDSHA256), testSHA256("chronology-introduced-member"))
	slices.Sort(finalUIDs)

	t.Run("post-plan inventory passes", func(t *testing.T) {
		planPath := writeHAWaveJSON(t, "plan.json", plan)
		opts := haWaveVerifyOptions(t, planPath, "backup.json", base, 2, nil)
		opts.LoadInventory = inventoryLoaderForUIDs(base, plan.InstallationID, finalUIDs, nil)
		report := VerifyHAWave(opts)
		if report.Status != "ready" {
			t.Fatalf("strictly ordered verification inventory was rejected: %+v", report)
		}
	})

	planGeneratedAt, err := parseHAWaveTime(plan.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		capturedAt time.Time
	}{
		{name: "inventory equal to plan generation", capturedAt: planGeneratedAt},
		{name: "fresh target inventory from before the plan", capturedAt: planGeneratedAt.Add(-time.Second)},
		{name: "inventory one nanosecond after verifier time", capturedAt: base.Add(time.Nanosecond)},
		{name: "inventory at maximum generic future skew", capturedAt: base.Add(maximumHAWaveFutureSkew)},
	} {
		t.Run(test.name, func(t *testing.T) {
			planPath := writeHAWaveJSON(t, "plan.json", plan)
			opts := haWaveVerifyOptions(t, planPath, "backup.json", base, 2, nil)
			opts.LoadInventory = inventoryLoaderForUIDs(test.capturedAt, plan.InstallationID, finalUIDs, nil)
			report := VerifyHAWave(opts)
			assertHAWaveBlocker(t, report.Blockers, "ha_wave_inventory_receipt_invalid")
		})
	}

	t.Run("inventory equal to newer bound backup", func(t *testing.T) {
		backupBoundaryPlan := plan
		backupBoundaryPlan.GeneratedAt = base.Add(-2 * time.Minute).Format(time.RFC3339Nano)
		backupBoundaryPlan.PreflightCapturedAt = backupBoundaryPlan.GeneratedAt
		backupBoundaryPlan.BackupGeneratedAt = base.Add(-time.Minute).Format(time.RFC3339Nano)
		planPath := writeHAWaveJSON(t, "backup-boundary-plan.json", backupBoundaryPlan)
		opts := haWaveVerifyOptions(t, planPath, "backup.json", base, 2, nil)
		opts.LoadInventory = inventoryLoaderForUIDs(base.Add(-time.Minute), plan.InstallationID, finalUIDs, nil)
		report := VerifyHAWave(opts)
		assertHAWaveBlocker(t, report.Blockers, "ha_wave_inventory_receipt_invalid")
	})

	for _, test := range []struct {
		name   string
		offset time.Duration
		field  string
	}{
		{name: "plan one nanosecond after verifier time", offset: time.Nanosecond, field: "plan"},
		{name: "plan at maximum generic future skew", offset: maximumHAWaveFutureSkew, field: "plan"},
		{name: "backup one nanosecond after verifier time", offset: time.Nanosecond, field: "backup"},
		{name: "backup at maximum generic future skew", offset: maximumHAWaveFutureSkew, field: "backup"},
	} {
		t.Run(test.name, func(t *testing.T) {
			futurePlan := plan
			if test.field == "plan" {
				futurePlan.GeneratedAt = base.Add(test.offset).Format(time.RFC3339Nano)
				futurePlan.PreflightCapturedAt = futurePlan.GeneratedAt
			} else {
				futurePlan.BackupGeneratedAt = base.Add(test.offset).Format(time.RFC3339Nano)
			}
			planPath := writeHAWaveJSON(t, "future-plan.json", futurePlan)
			opts := haWaveVerifyOptions(t, planPath, "backup.json", base, 2, nil)
			report := VerifyHAWave(opts)
			assertHAWaveBlocker(t, report.Blockers, "ha_wave_plan_invalid")
		})
	}
}

func TestHAWaveFinalReceiptChronologyRejectsEqualityAndOlderSameSetReuse(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	plan := readyHAWavePlanForTest(base, HAWavePhaseTwoToThree)
	planGeneratedAt, err := parseHAWaveTime(plan.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	backupGeneratedAt, err := parseHAWaveTime(plan.BackupGeneratedAt)
	if err != nil {
		t.Fatal(err)
	}

	verify := func(t *testing.T, testPlan HAWavePlan, completedAt, inventoryCapturedAt time.Time) HAWaveVerification {
		t.Helper()
		planPath := writeHAWaveJSON(t, "plan.json", testPlan)
		receipt := testOneServerLossReceipt()
		shiftTestOneServerLossReceipt(t, &receipt, completedAt)
		opts := haWaveVerifyOptions(t, planPath, "backup.json", inventoryCapturedAt, 3, &receipt)
		opts.FinalOneServerLossPath = "receipt.json"
		opts.LoadOneServerLossReceipt = func(string, time.Time) (*oneserverloss.Receipt, string, error) {
			return &receipt, testSHA256("receipt-artifact"), nil
		}
		return VerifyHAWave(opts)
	}

	t.Run("strict chronology passes", func(t *testing.T) {
		report := verify(t, plan, planGeneratedAt.Add(30*time.Second), base)
		if report.Status != "ready" || !report.FinalOneServerLossVerified {
			t.Fatalf("strict final evidence chronology was rejected: %+v", report)
		}
	})

	for _, test := range []struct {
		name                string
		testPlan            HAWavePlan
		completedAt         time.Time
		inventoryCapturedAt time.Time
	}{
		{
			name:                "completion equal to plan generation",
			testPlan:            plan,
			completedAt:         planGeneratedAt,
			inventoryCapturedAt: base,
		},
		{
			name:                "binding inventory equal to drill completion",
			testPlan:            plan,
			completedAt:         base,
			inventoryCapturedAt: base,
		},
		{
			name:                "fresh older receipt from the same final member set",
			testPlan:            plan,
			completedAt:         planGeneratedAt.Add(-time.Second),
			inventoryCapturedAt: base,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := verify(t, test.testPlan, test.completedAt, test.inventoryCapturedAt)
			if test.name == "fresh older receipt from the same final member set" {
				transition, found := findHAWaveCheck(report.Checks, "member_identity_transition")
				if !found || transition.Status != "pass" || report.Observed != haWaveCounts(3) {
					t.Fatalf("receipt-reuse fixture did not preserve the exact final member set: %+v", report)
				}
			}
			assertHAWaveBlocker(t, report.Blockers, "ha_wave_final_one_server_loss_invalid")
		})
	}

	t.Run("completion equal to newer bound backup", func(t *testing.T) {
		report := verify(t, plan, backupGeneratedAt, base)
		assertHAWaveBlocker(t, report.Blockers, "ha_wave_final_one_server_loss_invalid")
	})

	if !backupGeneratedAt.Before(planGeneratedAt) {
		t.Fatalf("test plan does not place its backup before plan generation: backup=%s plan=%s", backupGeneratedAt, planGeneratedAt)
	}
}

func TestHAWaveFinalReceiptValidationRejectsFutureCompletionAndInventory(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	plan := readyHAWavePlanForTest(base, HAWavePhaseTwoToThree)
	planGeneratedAt, err := parseHAWaveTime(plan.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	backupGeneratedAt, err := parseHAWaveTime(plan.BackupGeneratedAt)
	if err != nil {
		t.Fatal(err)
	}

	for _, offset := range []time.Duration{time.Nanosecond, maximumHAWaveFutureSkew} {
		t.Run(offset.String(), func(t *testing.T) {
			receipt := testOneServerLossReceipt()
			completedAt := base.Add(offset)
			shiftTestOneServerLossReceipt(t, &receipt, completedAt)
			planPath := writeHAWaveJSON(t, "future-receipt-plan.json", plan)
			opts := haWaveVerifyOptions(t, planPath, "backup.json", completedAt.Add(time.Nanosecond), 3, &receipt)
			inventory, _, loadErr := opts.LoadInventory(opts.InventoryPath, base)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if validateErr := validateHAWaveOneServerLossReceipt(
				&receipt,
				inventory,
				plan.Target,
				base,
				planGeneratedAt,
				backupGeneratedAt,
			); validateErr == nil {
				t.Fatal("future-dated final drill and binding inventory unexpectedly passed")
			}
		})
	}
}

func TestHAWaveFinalReceiptMustMatchInventoryDigestAndIdentityBinding(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	planPath := writeHAWaveJSON(t, "second-plan.json", readyHAWavePlanForTest(base, HAWavePhaseTwoToThree))
	receipt := testOneServerLossReceipt()
	opts := haWaveVerifyOptions(t, planPath, "backup.json", base, 3, &receipt)
	opts.FinalOneServerLossPath = "receipt.json"
	opts.LoadOneServerLossReceipt = func(string, time.Time) (*oneserverloss.Receipt, string, error) {
		return &receipt, testSHA256("receipt-artifact"), nil
	}
	originalLoader := opts.LoadInventory
	opts.LoadInventory = func(path string, now time.Time) (*HAWaveInventoryReceipt, string, error) {
		inventory, sha, err := originalLoader(path, now)
		if err != nil {
			return nil, "", err
		}
		copy := *inventory
		copy.OneServerLossReceiptBinding.TargetNodeUIDSHA256 = testSHA256("different-node")
		copy.ReceiptSHA256 = HAWaveInventoryReceiptSHA256(copy)
		return &copy, sha, nil
	}
	report := VerifyHAWave(opts)
	assertHAWaveBlocker(t, report.Blockers, "ha_wave_final_one_server_loss_invalid")
}

func TestHAWaveFinalReceiptRejectsSameCountCrossTopologyMemberSet(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	plan := readyHAWavePlanForTest(base, HAWavePhaseTwoToThree)
	planPath := writeHAWaveJSON(t, "second-plan.json", plan)
	receipt := testOneServerLossReceipt()
	opts := haWaveVerifyOptions(t, planPath, "backup.json", base, 3, &receipt)
	finalUIDs := append(slices.Clone(plan.StartingMemberUIDSHA256), receipt.TargetNodeUIDSHA256)
	slices.Sort(finalUIDs)
	crossTopologyUIDs := []string{receipt.TargetNodeUIDSHA256, testSHA256("other-topology-a"), testSHA256("other-topology-b")}
	slices.Sort(crossTopologyUIDs)
	bindTestOneServerLossReceiptToMembers(&receipt, crossTopologyUIDs)
	opts.LoadInventory = inventoryLoaderForUIDs(base, plan.InstallationID, finalUIDs, &receipt)
	opts.FinalOneServerLossPath = "receipt.json"
	opts.LoadOneServerLossReceipt = func(string, time.Time) (*oneserverloss.Receipt, string, error) {
		return &receipt, testSHA256("receipt-artifact"), nil
	}
	report := VerifyHAWave(opts)
	identityCheck, found := findHAWaveCheck(report.Checks, "member_identity_transition")
	if !found || identityCheck.Status != "pass" {
		t.Fatalf("test final inventory did not satisfy the exact plan transition: %+v", report)
	}
	assertHAWaveBlocker(t, report.Blockers, "ha_wave_final_one_server_loss_invalid")
}

func TestHAWaveFinalReceiptWithoutFullMemberSetRemainsGenericallyValidButIsRejected(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	plan := readyHAWavePlanForTest(base, HAWavePhaseTwoToThree)
	planPath := writeHAWaveJSON(t, "second-plan.json", plan)
	receipt := testOneServerLossReceipt()
	opts := haWaveVerifyOptions(t, planPath, "backup.json", base, 3, &receipt)
	receipt.NodeUIDHashAlgorithm = ""
	receipt.Baseline.ControlPlaneMemberSetSHA256 = ""
	for _, phase := range []*oneserverloss.PhaseEvidence{&receipt.PreLoss, &receipt.Loss, &receipt.Recovered} {
		for index := range phase.Samples {
			phase.Samples[index].ControlPlaneMemberSetSHA256 = ""
		}
	}
	rehashTestReceipt(&receipt)
	if err := oneserverloss.ValidateReceipt(&receipt); err != nil {
		t.Fatalf("generic receipt compatibility unexpectedly rejected old receipt shape: %v", err)
	}
	finalUIDs := append(slices.Clone(plan.StartingMemberUIDSHA256), receipt.TargetNodeUIDSHA256)
	slices.Sort(finalUIDs)
	opts.LoadInventory = inventoryLoaderForUIDs(base, plan.InstallationID, finalUIDs, &receipt)
	opts.FinalOneServerLossPath = "receipt.json"
	opts.LoadOneServerLossReceipt = func(string, time.Time) (*oneserverloss.Receipt, string, error) {
		return &receipt, testSHA256("receipt-artifact"), nil
	}
	report := VerifyHAWave(opts)
	assertHAWaveBlocker(t, report.Blockers, "ha_wave_final_one_server_loss_invalid")
}

func TestHAWaveVerificationBindsExactStartingMemberSetPlusOneIntroduction(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	firstPlan := readyHAWavePlanForTest(base, HAWavePhaseOneToTwo)
	firstPlanPath := writeHAWaveJSON(t, "first-plan.json", firstPlan)
	firstStart := slices.Clone(firstPlan.StartingMemberUIDSHA256)

	t.Run("exact union is ready and records rollback identity", func(t *testing.T) {
		introduced := testSHA256("exactly-one-introduced-member")
		finalUIDs := append(slices.Clone(firstStart), introduced)
		slices.Sort(finalUIDs)
		opts := haWaveVerifyOptions(t, firstPlanPath, "backup.json", base, 2, nil)
		opts.LoadInventory = inventoryLoaderForUIDs(base, firstPlan.InstallationID, finalUIDs, nil)
		report := VerifyHAWave(opts)
		if report.Status != "ready" || report.IntroducedMemberUIDSHA256 != introduced {
			t.Fatalf("exact identity union was not accepted and recorded: %+v", report)
		}
		if !slices.Equal(report.StartingMemberUIDSHA256, firstStart) || !slices.Equal(report.FinalMemberUIDSHA256, finalUIDs) {
			t.Fatalf("verification did not persist exact privacy-safe identity sets: %+v", report)
		}
	})

	t.Run("replacement with the same target counts", func(t *testing.T) {
		finalUIDs := []string{testSHA256("replacement-a"), testSHA256("replacement-b")}
		slices.Sort(finalUIDs)
		opts := haWaveVerifyOptions(t, firstPlanPath, "backup.json", base, 2, nil)
		opts.LoadInventory = inventoryLoaderForUIDs(base, firstPlan.InstallationID, finalUIDs, nil)
		report := VerifyHAWave(opts)
		if report.Observed != haWaveCounts(2) {
			t.Fatalf("test did not preserve target counts: %+v", report.Observed)
		}
		assertHAWaveBlocker(t, report.Blockers, "ha_wave_member_identity_transition_invalid")
	})

	secondPlan := readyHAWavePlanForTest(base, HAWavePhaseTwoToThree)
	secondPlanPath := writeHAWaveJSON(t, "second-plan.json", secondPlan)
	receipt := testOneServerLossReceipt()
	verifySecond := func(t *testing.T, finalUIDs []string) HAWaveVerification {
		t.Helper()
		slices.Sort(finalUIDs)
		opts := haWaveVerifyOptions(t, secondPlanPath, "backup.json", base, 3, &receipt)
		opts.LoadInventory = inventoryLoaderForUIDs(base, secondPlan.InstallationID, finalUIDs, &receipt)
		opts.FinalOneServerLossPath = "receipt.json"
		opts.LoadOneServerLossReceipt = func(string, time.Time) (*oneserverloss.Receipt, string, error) {
			return &receipt, testSHA256("receipt-artifact"), nil
		}
		return VerifyHAWave(opts)
	}

	t.Run("entirely different final set", func(t *testing.T) {
		report := verifySecond(t, []string{receipt.TargetNodeUIDSHA256, testSHA256("different-a"), testSHA256("different-b")})
		if report.Observed != haWaveCounts(3) {
			t.Fatalf("test did not preserve target counts: %+v", report.Observed)
		}
		assertHAWaveBlocker(t, report.Blockers, "ha_wave_member_identity_transition_invalid")
	})

	t.Run("two additions and one deletion", func(t *testing.T) {
		report := verifySecond(t, []string{
			secondPlan.StartingMemberUIDSHA256[0],
			receipt.TargetNodeUIDSHA256,
			testSHA256("second-unexpected-addition"),
		})
		if report.Observed != haWaveCounts(3) {
			t.Fatalf("test did not preserve target counts: %+v", report.Observed)
		}
		assertHAWaveBlocker(t, report.Blockers, "ha_wave_member_identity_transition_invalid")
	})
}

func TestHAWaveRejectsDuplicateAndMalformedMemberIdentities(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)

	t.Run("duplicate preflight identities", func(t *testing.T) {
		duplicate := testSHA256("duplicate-member")
		inventory := testHAWaveInventoryReceiptWithUIDs(base, "synthetic-cell-001", []string{duplicate, duplicate}, nil)
		opts := HAWavePlanOptions{
			InstallationID: "synthetic-cell-001", Current: haWaveCounts(2), PreflightInventoryPath: "preflight.json",
			LoadPreflightInventory: func(string, time.Time) (*HAWaveInventoryReceipt, string, error) {
				return inventory, testSHA256("preflight-artifact"), nil
			},
			BackupBarrierPath: "backup.json", Now: fixedHAWaveClock(base), ValidateBackup: passingHAWaveBackup(base, "backup"),
		}
		assertHAWaveBlocker(t, BuildHAWavePlan(opts).Blockers, "ha_wave_preflight_inventory_invalid")
		if digest := HAWaveMemberSetSHA256([]string{duplicate, duplicate}); digest != "" {
			t.Fatalf("duplicate identity set produced digest %q", digest)
		}
	})

	for _, test := range []struct {
		name string
		uids []string
	}{
		{name: "duplicate final identities", uids: []string{testSHA256("duplicate-final"), testSHA256("duplicate-final")}},
		{name: "malformed final identity", uids: []string{testSHA256("valid-final"), "not-a-sha256"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := readyHAWavePlanForTest(base, HAWavePhaseOneToTwo)
			planPath := writeHAWaveJSON(t, "plan.json", plan)
			opts := haWaveVerifyOptions(t, planPath, "backup.json", base, 2, nil)
			opts.LoadInventory = inventoryLoaderForUIDs(base, plan.InstallationID, test.uids, nil)
			report := VerifyHAWave(opts)
			assertHAWaveBlocker(t, report.Blockers, "ha_wave_inventory_receipt_invalid")
			assertHAWaveBlocker(t, report.Blockers, "ha_wave_member_identity_transition_invalid")
		})
	}
}

func TestHAWaveRejectsAmbiguousNodeUIDHashAlgorithms(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	for _, algorithm := range []string{"", "sha256-json-string-v0"} {
		name := algorithm
		if name == "" {
			name = "missing"
		}
		t.Run(name, func(t *testing.T) {
			inventory := testHAWaveInventoryReceipt(base, "synthetic-cell-001", 1, nil)
			inventory.NodeUIDHashAlgorithm = algorithm
			inventory.ReceiptSHA256 = HAWaveInventoryReceiptSHA256(*inventory)
			plan := BuildHAWavePlan(HAWavePlanOptions{
				InstallationID: "synthetic-cell-001", Current: haWaveCounts(1),
				PreflightInventoryPath: "preflight.json",
				LoadPreflightInventory: func(string, time.Time) (*HAWaveInventoryReceipt, string, error) {
					return inventory, testSHA256("preflight-artifact"), nil
				},
				BackupBarrierPath: "backup.json", ValidateBackup: passingHAWaveBackup(base, "backup"), Now: fixedHAWaveClock(base),
			})
			assertHAWaveBlocker(t, plan.Blockers, "ha_wave_preflight_inventory_invalid")
		})
	}
}

func TestHAWaveMemberSetDigestIsCanonicalAndDomainSeparated(t *testing.T) {
	first := testSHA256("canonical-first")
	second := testSHA256("canonical-second")
	forward := HAWaveMemberSetSHA256([]string{first, second})
	reverse := HAWaveMemberSetSHA256([]string{second, first})
	if !validHAWaveSHA256(forward) || reverse != forward {
		t.Fatalf("member-set digest is not deterministic across ordering: forward=%q reverse=%q", forward, reverse)
	}
	canonicalUIDs := []string{first, second}
	slices.Sort(canonicalUIDs)
	plainPayload, err := json.Marshal(canonicalUIDs)
	if err != nil {
		t.Fatal(err)
	}
	if forward == testSHA256(string(plainPayload)) {
		t.Fatal("member-set digest omitted its schema domain")
	}
}

func TestHAWaveAcceptsCanonicalObserverNodeUIDHashContract(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	startingUIDs := []string{
		kubeidentity.NodeUIDSHA256("observer-node-uid-a"),
		kubeidentity.NodeUIDSHA256("observer-node-uid-b"),
	}
	slices.Sort(startingUIDs)
	introducedUID := kubeidentity.NodeUIDSHA256("observer-node-uid-c")
	plan := readyHAWavePlanForTest(base, HAWavePhaseTwoToThree)
	plan.StartingMemberUIDSHA256 = startingUIDs
	plan.StartingMemberSetSHA256 = HAWaveMemberSetSHA256(startingUIDs)
	planPath := writeHAWaveJSON(t, "observer-contract-plan.json", plan)

	receipt := testOneServerLossReceipt()
	receipt.TargetNodeUIDSHA256 = introducedUID
	for _, phase := range []*oneserverloss.PhaseEvidence{&receipt.PreLoss, &receipt.Loss, &receipt.Recovered} {
		for index := range phase.Samples {
			if phase.Samples[index].TargetNodePresent {
				phase.Samples[index].TargetNodeUIDSHA256 = introducedUID
			}
		}
	}
	rehashTestReceipt(&receipt)
	opts := haWaveVerifyOptions(t, planPath, "backup.json", base, 3, &receipt)
	opts.FinalOneServerLossPath = "observer-receipt.json"
	opts.LoadOneServerLossReceipt = func(string, time.Time) (*oneserverloss.Receipt, string, error) {
		return &receipt, testSHA256("observer-receipt-artifact"), nil
	}
	report := VerifyHAWave(opts)
	if report.Status != "ready" || report.NodeUIDHashAlgorithm != kubeidentity.NodeUIDHashAlgorithm ||
		report.IntroducedMemberUIDSHA256 != introducedUID {
		t.Fatalf("observer and HA-wave Node UID hash contracts did not integrate: %+v", report)
	}
}

func TestHAWaveIdentityBindingRejectsPlanAndVerificationTampering(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	plan := readyHAWavePlanForTest(base, HAWavePhaseOneToTwo)

	tamperedPlan := plan
	tamperedPlan.StartingMemberUIDSHA256 = []string{testSHA256("replaced-start")}
	if _, _, err := ReadHAWavePlan(writeHAWaveJSON(t, "tampered-plan.json", tamperedPlan)); err == nil {
		t.Fatal("plan whose starting identities no longer match its digest was accepted")
	}
	tamperedPlan = plan
	tamperedPlan.PreflightCapturedAt = ""
	if _, _, err := ReadHAWavePlan(writeHAWaveJSON(t, "tampered-preflight-time-plan.json", tamperedPlan)); err == nil {
		t.Fatal("plan without its bound preflight capture time was accepted")
	}
	secondPlan := readyHAWavePlanForTest(base, HAWavePhaseTwoToThree)
	secondPlan.PreflightCapturedAt = secondPlan.BackupGeneratedAt
	if _, _, err := ReadHAWavePlan(writeHAWaveJSON(t, "tampered-interwave-time-plan.json", secondPlan)); err == nil {
		t.Fatal("two-to-three plan whose preflight does not follow its backup was accepted")
	}

	planPath := writeHAWaveJSON(t, "plan.json", plan)
	verification := VerifyHAWave(haWaveVerifyOptions(t, planPath, "backup.json", base, 2, nil))
	if verification.Status != "ready" {
		t.Fatalf("test verification is not ready: %+v", verification)
	}
	tamperedVerification := verification
	tamperedVerification.IntroducedMemberUIDSHA256 = testSHA256("forged-rollback-target")
	if _, _, err := ReadHAWaveVerification(writeHAWaveJSON(t, "tampered-verification.json", tamperedVerification)); err == nil {
		t.Fatal("verification with a forged introduced rollback identity was accepted")
	}
}

func TestHAWavePlanFailsClosedOnInvalidInputs(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	tests := []struct {
		name    string
		opts    HAWavePlanOptions
		blocker string
	}{
		{
			name: "missing preflight inventory",
			opts: HAWavePlanOptions{InstallationID: "synthetic-cell-001", Current: haWaveCounts(1),
				BackupBarrierPath: "backup.json", Now: fixedHAWaveClock(base), ValidateBackup: passingHAWaveBackup(base, "backup")},
			blocker: "ha_wave_preflight_inventory_invalid",
		},
		{
			name: "mismatched topology",
			opts: HAWavePlanOptions{InstallationID: "synthetic-cell-001", Current: HAWaveCounts{ControlPlane: 1, Etcd: 1, APIServer: 0},
				BackupBarrierPath: "backup.json", Now: fixedHAWaveClock(base), ValidateBackup: passingHAWaveBackup(base, "backup")},
			blocker: "ha_wave_current_topology_invalid",
		},
		{
			name: "unsafe installation id",
			opts: HAWavePlanOptions{InstallationID: "https://private.invalid/cell", Current: haWaveCounts(1),
				BackupBarrierPath: "backup.json", Now: fixedHAWaveClock(base), ValidateBackup: passingHAWaveBackup(base, "backup")},
			blocker: "ha_wave_installation_id_invalid",
		},
		{
			name: "missing backup validator",
			opts: HAWavePlanOptions{InstallationID: "synthetic-cell-001", Current: haWaveCounts(1),
				BackupBarrierPath: "backup.json", Now: fixedHAWaveClock(base)},
			blocker: "ha_wave_backup_validator_missing",
		},
		{
			name: "stale backup",
			opts: HAWavePlanOptions{InstallationID: "synthetic-cell-001", Current: haWaveCounts(1),
				BackupBarrierPath: "backup.json", Now: fixedHAWaveClock(base), ValidateBackup: passingHAWaveBackup(base.Add(-maximumHAWaveEvidenceAge-time.Second), "backup")},
			blocker: "ha_wave_backup_invalid",
		},
		{
			name: "unsafe backup artifact basename",
			opts: HAWavePlanOptions{InstallationID: "synthetic-cell-001", Current: haWaveCounts(1),
				BackupBarrierPath: ".backup.json", Now: fixedHAWaveClock(base), ValidateBackup: passingHAWaveBackup(base, "backup")},
			blocker: "ha_wave_backup_artifact_invalid",
		},
		{
			name: "invalid clock",
			opts: HAWavePlanOptions{InstallationID: "synthetic-cell-001", Current: haWaveCounts(1),
				BackupBarrierPath: "backup.json", Now: fixedHAWaveClock(time.Time{}), ValidateBackup: passingHAWaveBackup(base, "backup")},
			blocker: "ha_wave_clock_invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.name != "missing preflight inventory" {
				count := test.opts.Current.ControlPlane
				if count < 1 || count > 3 {
					count = 1
				}
				test.opts = withHAWavePreflight(test.opts, base, count)
			}
			plan := BuildHAWavePlan(test.opts)
			if plan.Status != "blocked" || plan.MutationAllowed {
				t.Fatalf("invalid input did not fail closed: %+v", plan)
			}
			assertHAWaveBlocker(t, plan.Blockers, test.blocker)
		})
	}
}

func TestHAWavePlanFailsClosedOnPreflightLoaderNilAndError(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	validInventory := testHAWaveInventoryReceipt(base, "synthetic-cell-001", 1, nil)
	for _, test := range []struct {
		name string
		load HAWaveInventoryLoader
	}{
		{
			name: "nil receipt without error",
			load: func(string, time.Time) (*HAWaveInventoryReceipt, string, error) {
				return nil, testSHA256("inventory-artifact"), nil
			},
		},
		{
			name: "nil receipt with error",
			load: func(string, time.Time) (*HAWaveInventoryReceipt, string, error) {
				return nil, "", errors.New("synthetic loader failure")
			},
		},
		{
			name: "receipt returned with error",
			load: func(string, time.Time) (*HAWaveInventoryReceipt, string, error) {
				return validInventory, testSHA256("inventory-artifact"), errors.New("synthetic partial loader failure")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := BuildHAWavePlan(HAWavePlanOptions{
				InstallationID: "synthetic-cell-001", Current: haWaveCounts(1),
				PreflightInventoryPath: "preflight.json", LoadPreflightInventory: test.load,
				BackupBarrierPath: "backup.json", ValidateBackup: passingHAWaveBackup(base, "backup"), Now: fixedHAWaveClock(base),
			})
			if plan.Status != "blocked" || plan.MutationAllowed {
				t.Fatalf("unsafe loader result did not fail closed: %+v", plan)
			}
			assertHAWaveBlocker(t, plan.Blockers, "ha_wave_preflight_inventory_invalid")
		})
	}
}

func TestHAWaveVerificationRejectsUnsafeArtifactBasenames(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	planPath := writeHAWaveJSON(t, "first-plan.json", readyHAWavePlanForTest(base, HAWavePhaseOneToTwo))
	t.Run("plan", func(t *testing.T) {
		payload, err := os.ReadFile(planPath) // #nosec G304 -- planPath is created by this test beneath t.TempDir.
		if err != nil {
			t.Fatal(err)
		}
		hiddenPlan := filepath.Join(t.TempDir(), ".plan.json")
		if err := os.WriteFile(hiddenPlan, payload, 0o600); err != nil { // #nosec G703 -- hiddenPlan is a fixed filename beneath this test's private t.TempDir.
			t.Fatal(err)
		}
		opts := haWaveVerifyOptions(t, planPath, "backup.json", base, 2, nil)
		opts.PlanPath = hiddenPlan
		assertHAWaveBlocker(t, VerifyHAWave(opts).Blockers, "ha_wave_plan_invalid")
	})
	t.Run("backup", func(t *testing.T) {
		opts := haWaveVerifyOptions(t, planPath, "backup.json", base, 2, nil)
		opts.BackupBarrierPath = ".backup.json"
		assertHAWaveBlocker(t, VerifyHAWave(opts).Blockers, "ha_wave_backup_revalidation_invalid")
	})
	t.Run("inventory", func(t *testing.T) {
		opts := haWaveVerifyOptions(t, planPath, "backup.json", base, 2, nil)
		opts.InventoryPath = ".inventory.json"
		assertHAWaveBlocker(t, VerifyHAWave(opts).Blockers, "ha_wave_inventory_receipt_invalid")
	})
	t.Run("final receipt", func(t *testing.T) {
		finalPlanPath := writeHAWaveJSON(t, "second-plan.json", readyHAWavePlanForTest(base, HAWavePhaseTwoToThree))
		receipt := testOneServerLossReceipt()
		opts := haWaveVerifyOptions(t, finalPlanPath, "backup.json", base, 3, &receipt)
		opts.FinalOneServerLossPath = ".receipt.json"
		opts.LoadOneServerLossReceipt = func(string, time.Time) (*oneserverloss.Receipt, string, error) {
			return &receipt, testSHA256("receipt-artifact"), nil
		}
		assertHAWaveBlocker(t, VerifyHAWave(opts).Blockers, "ha_wave_final_one_server_loss_invalid")
	})
}

func TestReadHAWaveEvidenceRejectsUnknownDuplicateTrailingAndMutation(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	plan := BuildHAWavePlan(withHAWavePreflight(HAWavePlanOptions{
		InstallationID: "synthetic-cell-001", Current: haWaveCounts(1), BackupBarrierPath: "backup.json",
		Now: fixedHAWaveClock(base), ValidateBackup: passingHAWaveBackup(base.Add(-time.Minute), "backup"),
	}, base, 1))
	payload, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(nil), payload[:len(payload)-1]...)
	unknown = append(unknown, []byte(`,"unexpected":true}`)...)
	duplicate := []byte(`{"schemaVersion":"cloudring.kubeadm.ha-wave/v2","schemaVersion":"cloudring.kubeadm.ha-wave/v2"}`)
	trailing := append(append([]byte(nil), payload...), []byte(`{}`)...)
	mutatedPlan := plan
	mutatedPlan.MutationAllowed = true
	mutated, err := json.Marshal(mutatedPlan)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		payload []byte
	}{
		{"unknown", unknown},
		{"duplicate", duplicate},
		{"trailing", trailing},
		{"mutation allowed", mutated},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "plan.json")
			if err := os.WriteFile(path, test.payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := ReadHAWavePlan(path); err == nil {
				t.Fatal("unsafe HA-wave evidence was accepted")
			}
		})
	}
}

func TestReadHAWaveVerificationRequiresExactOrderedVerificationChecks(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	planPath := writeHAWaveJSON(t, "first-plan.json", readyHAWavePlanForTest(base, HAWavePhaseOneToTwo))
	ready := VerifyHAWave(haWaveVerifyOptions(t, planPath, "backup.json", base, 2, nil))
	if ready.Status != "ready" {
		t.Fatalf("test verification is not ready: %+v", ready)
	}

	missingBoundChecks := ready
	missingBoundChecks.Checks = []HAWaveCheck{
		{ID: "current_topology", Status: "pass", Detail: "fabricated topology"},
		{ID: "fresh_backup", Status: "pass", Artifact: "backup.json", SHA256: testSHA256("fabricated-backup"), Detail: "fabricated backup"},
	}
	if _, _, err := ReadHAWaveVerification(writeHAWaveJSON(t, "missing-checks.json", missingBoundChecks)); err == nil {
		t.Fatal("verification without plan, inventory, and target checks was accepted")
	}

	reordered := ready
	reordered.Checks = append([]HAWaveCheck(nil), ready.Checks...)
	reordered.Checks[0], reordered.Checks[1] = reordered.Checks[1], reordered.Checks[0]
	if _, _, err := ReadHAWaveVerification(writeHAWaveJSON(t, "reordered-checks.json", reordered)); err == nil {
		t.Fatal("verification with reordered checks was accepted")
	}
}

func TestReadHAWavePlanCannotUseVerificationShapedChecks(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	plan := readyHAWavePlanForTest(base, HAWavePhaseTwoToThree)
	plan.Checks = []HAWaveCheck{
		{ID: "plan", Status: "pass", Artifact: "plan.json", SHA256: testSHA256("plan"), Detail: "fabricated plan"},
		{ID: "fresh_backup", Status: "pass", Artifact: "backup.json", SHA256: testSHA256("backup"), Detail: "fabricated backup"},
		{ID: "inventory", Status: "pass", Artifact: "inventory.json", SHA256: testSHA256("inventory"), Detail: "fabricated inventory"},
		{ID: "target_topology", Status: "pass", Detail: "fabricated target"},
		{ID: "final_one_server_loss", Status: "pass", Artifact: "receipt.json", SHA256: testSHA256("receipt"), Detail: "fabricated receipt"},
	}
	if _, _, err := ReadHAWavePlan(writeHAWaveJSON(t, "verification-shaped-plan.json", plan)); err == nil {
		t.Fatal("plan with verification-shaped checks was accepted")
	}
}

func TestReadHAWaveEvidenceRejectsOversizedInputBeforeDecode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized-plan.json")
	if err := os.WriteFile(path, make([]byte, strictjson.MaxDocumentBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadHAWavePlan(path); err == nil {
		t.Fatal("oversized HA-wave evidence was accepted")
	}
}

func TestHAWaveReportsDoNotCopyPrivatePaths(t *testing.T) {
	base := time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC)
	privatePrefix := filepath.Join("private", "installation", "records")
	opts := withHAWavePreflight(HAWavePlanOptions{
		InstallationID: "synthetic-cell-001", Current: haWaveCounts(1),
		BackupBarrierPath: filepath.Join(privatePrefix, "backup.json"), Now: fixedHAWaveClock(base),
		ValidateBackup: passingHAWaveBackup(base.Add(-time.Minute), "backup"),
	}, base, 1)
	opts.PreflightInventoryPath = filepath.Join(privatePrefix, "preflight.json")
	plan := BuildHAWavePlan(opts)
	payload, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), privatePrefix) || !strings.Contains(string(payload), `"artifact":"preflight.json"`) ||
		!strings.Contains(string(payload), `"artifact":"backup.json"`) {
		t.Fatalf("plan evidence was not source-safe: %s", payload)
	}
}

func readyHAWavePlanForTest(now time.Time, phase string) HAWavePlan {
	generatedAt := now.Add(-time.Minute)
	backupGeneratedAt := now.Add(-2 * time.Minute)
	from := 1
	startingUIDs := testHAWaveMemberUIDs(from)
	checks := []HAWaveCheck{
		{ID: "preflight_inventory", Status: "pass", Artifact: "preflight-inventory.json", SHA256: testSHA256("preflight-inventory-artifact"), Detail: "starting control-plane and etcd member identities are bound by canonical SHA-256"},
		{ID: "current_topology", Status: "pass", Detail: "phase=one-to-two members=1"},
		{ID: "fresh_backup", Status: "pass", Artifact: "backup.json", SHA256: testSHA256("backup"), Detail: "fresh off-cell backup and restore barrier is valid"},
	}
	if phase == HAWavePhaseTwoToThree {
		from = 2
		startingUIDs = testHAWaveMemberUIDs(from)
		checks[1].Detail = "phase=two-to-three members=2"
		checks = append(checks, HAWaveCheck{ID: "previous_wave", Status: "pass", Artifact: "previous.json", SHA256: testSHA256("previous"), Detail: "one-to-two verification is ready and the inter-wave backup is newer"})
	}
	return HAWavePlan{
		SchemaVersion: HAWaveSchemaVersion, GeneratedAt: generatedAt.Format(time.RFC3339Nano), Status: "ready", Phase: phase,
		InstallationID: "synthetic-cell-001", From: haWaveCounts(from), Target: haWaveCounts(from + 1),
		PreflightInventoryReceiptSHA256: testSHA256("preflight-inventory-receipt"), PreflightCapturedAt: generatedAt.Format(time.RFC3339Nano),
		NodeUIDHashAlgorithm:    kubeidentity.NodeUIDHashAlgorithm,
		StartingMemberUIDSHA256: startingUIDs,
		StartingMemberSetSHA256: HAWaveMemberSetSHA256(startingUIDs),
		BackupGeneratedAt:       backupGeneratedAt.Format(time.RFC3339Nano), Checks: checks, Blockers: []string{},
		Steps: append([]string(nil), haWaveSteps...), Rollback: append([]string(nil), haWaveRollback...),
		MutationAllowed: false, NonClaim: haWavePlanNonClaim,
	}
}

func passingHAWaveBackup(generatedAt time.Time, digestSeed string) HAWaveBackupValidator {
	return func(string, string, time.Time) (time.Time, string, error) {
		return generatedAt, testSHA256(digestSeed), nil
	}
}

func haWaveVerifyOptions(t *testing.T, planPath, backupPath string, now time.Time, members int, receipt *oneserverloss.Receipt) HAWaveVerifyOptions {
	t.Helper()
	plan, _, err := ReadHAWavePlan(planPath)
	if err != nil {
		t.Fatalf("read test HA-wave plan: %v", err)
	}
	backupAt, err := parseHAWaveTime(plan.BackupGeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	backupCheck, ok := findHAWaveCheck(plan.Checks, "fresh_backup")
	if !ok {
		t.Fatal("test plan lacks fresh backup check")
	}
	if members != len(plan.StartingMemberUIDSHA256)+1 {
		t.Fatalf("test inventory member count %d does not advance plan start count %d by one", members, len(plan.StartingMemberUIDSHA256))
	}
	finalUIDs := slices.Clone(plan.StartingMemberUIDSHA256)
	introducedUID := kubeidentity.NodeUIDSHA256("wave-member-uid-" + strconv.Itoa(len(finalUIDs)))
	if receipt != nil && !slices.Contains(finalUIDs, receipt.TargetNodeUIDSHA256) {
		introducedUID = receipt.TargetNodeUIDSHA256
	}
	finalUIDs = append(finalUIDs, introducedUID)
	slices.Sort(finalUIDs)
	if receipt != nil {
		bindTestOneServerLossReceiptToMembers(receipt, finalUIDs)
	}
	inventory := testHAWaveInventoryReceiptWithUIDs(now, plan.InstallationID, finalUIDs, receipt)
	return HAWaveVerifyOptions{
		PlanPath:          planPath,
		BackupBarrierPath: backupPath,
		ValidateBackup: func(string, string, time.Time) (time.Time, string, error) {
			return backupAt, backupCheck.SHA256, nil
		},
		InventoryPath: "inventory.json",
		LoadInventory: func(string, time.Time) (*HAWaveInventoryReceipt, string, error) {
			return inventory, testSHA256("inventory-artifact"), nil
		},
		Now: fixedHAWaveClock(now),
	}
}

func testHAWaveInventoryReceipt(now time.Time, installationID string, count int, receipt *oneserverloss.Receipt) *HAWaveInventoryReceipt {
	uids := testHAWaveMemberUIDs(count)
	if receipt != nil && !slices.Contains(uids, receipt.TargetNodeUIDSHA256) {
		uids[len(uids)-1] = receipt.TargetNodeUIDSHA256
	}
	slices.Sort(uids)
	return testHAWaveInventoryReceiptWithUIDs(now, installationID, uids, receipt)
}

func testHAWaveInventoryReceiptWithUIDs(now time.Time, installationID string, uids []string, receipt *oneserverloss.Receipt) *HAWaveInventoryReceipt {
	members := make([]HAWaveMemberIdentity, 0, len(uids))
	for _, uid := range uids {
		members = append(members, HAWaveMemberIdentity{UIDSHA256: uid, Ready: true, ControlPlane: true, EtcdMember: true})
	}
	inventory := &HAWaveInventoryReceipt{
		SchemaVersion: HAWaveInventorySchemaVersion, CapturedAt: now.Format(time.RFC3339Nano), InstallationID: installationID,
		Distribution: "upstream", Bootstrap: "kubeadm", ServerVersion: "v1.35.6", NodeUIDHashAlgorithm: kubeidentity.NodeUIDHashAlgorithm, Members: members,
		APIServerNodeUIDSHA256: slices.Clone(uids),
	}
	if receipt != nil {
		inventory.OneServerLossReceiptBinding = OneServerLossReceiptBinding{
			ReceiptSHA256: receipt.ReceiptSHA256, RunNonceSHA256: receipt.RunNonceSHA256,
			TargetNodeUIDSHA256: receipt.TargetNodeUIDSHA256, KubectlExecutableSHA256: receipt.KubectlExecutableSHA256,
			ProbeAdapterSHA256: receipt.ProbeAdapterSHA256, NodeUIDHashAlgorithm: receipt.NodeUIDHashAlgorithm,
			ControlPlaneMemberSetSHA256: receipt.Baseline.ControlPlaneMemberSetSHA256,
		}
	}
	inventory.ReceiptSHA256 = HAWaveInventoryReceiptSHA256(*inventory)
	return inventory
}

func inventoryLoaderForUIDs(now time.Time, installationID string, uids []string, receipt *oneserverloss.Receipt) HAWaveInventoryLoader {
	inventory := testHAWaveInventoryReceiptWithUIDs(now, installationID, slices.Clone(uids), receipt)
	return func(string, time.Time) (*HAWaveInventoryReceipt, string, error) {
		return inventory, testSHA256("inventory-artifact"), nil
	}
}

func bindTestOneServerLossReceiptToMembers(receipt *oneserverloss.Receipt, memberUIDSHA256 []string) {
	if receipt == nil {
		return
	}
	fullSetSHA256 := HAWaveMemberSetSHA256(memberUIDSHA256)
	lossUIDs := make([]string, 0, len(memberUIDSHA256)-1)
	for _, uid := range memberUIDSHA256 {
		if uid != receipt.TargetNodeUIDSHA256 {
			lossUIDs = append(lossUIDs, uid)
		}
	}
	lossSetSHA256 := HAWaveMemberSetSHA256(lossUIDs)
	receipt.NodeUIDHashAlgorithm = kubeidentity.NodeUIDHashAlgorithm
	receipt.Baseline.ControlPlaneMemberSetSHA256 = fullSetSHA256
	for _, phase := range []*oneserverloss.PhaseEvidence{&receipt.PreLoss, &receipt.Loss, &receipt.Recovered} {
		setSHA256 := fullSetSHA256
		if phase.Phase == oneserverloss.PhaseLoss {
			setSHA256 = lossSetSHA256
		}
		for index := range phase.Samples {
			phase.Samples[index].ControlPlaneMemberSetSHA256 = setSHA256
		}
	}
	rehashTestReceipt(receipt)
}

func shiftTestOneServerLossReceipt(t *testing.T, receipt *oneserverloss.Receipt, completedAt time.Time) {
	t.Helper()
	currentCompletedAt, err := time.Parse(time.RFC3339Nano, receipt.CompletedAt)
	if err != nil {
		t.Fatalf("parse test one-server-loss completion: %v", err)
	}
	delta := completedAt.UTC().Sub(currentCompletedAt.UTC())
	shift := func(value string) string {
		parsed, parseErr := time.Parse(time.RFC3339Nano, value)
		if parseErr != nil {
			t.Fatalf("parse test one-server-loss timestamp %q: %v", value, parseErr)
		}
		return parsed.UTC().Add(delta).Format(time.RFC3339Nano)
	}
	receipt.StartedAt = shift(receipt.StartedAt)
	receipt.ReadyMarkerAt = shift(receipt.ReadyMarkerAt)
	receipt.CompletedAt = shift(receipt.CompletedAt)
	for _, phase := range []*oneserverloss.PhaseEvidence{&receipt.PreLoss, &receipt.Loss, &receipt.Recovered} {
		phase.StartedAt = shift(phase.StartedAt)
		phase.CompletedAt = shift(phase.CompletedAt)
		for index := range phase.Samples {
			phase.Samples[index].StartedAt = shift(phase.Samples[index].StartedAt)
			phase.Samples[index].ObservedAt = shift(phase.Samples[index].ObservedAt)
			phase.Samples[index].DataProbe.StartedAt = shift(phase.Samples[index].DataProbe.StartedAt)
			phase.Samples[index].DataProbe.CompletedAt = shift(phase.Samples[index].DataProbe.CompletedAt)
		}
	}
	rehashTestReceipt(receipt)
}

func testHAWaveMemberUIDs(count int) []string {
	uids := make([]string, 0, count)
	for index := 0; index < count; index++ {
		uids = append(uids, kubeidentity.NodeUIDSHA256("wave-member-uid-"+strconv.Itoa(index)))
	}
	slices.Sort(uids)
	return uids
}

func withHAWavePreflight(opts HAWavePlanOptions, capturedAt time.Time, count int) HAWavePlanOptions {
	inventory := testHAWaveInventoryReceipt(capturedAt, opts.InstallationID, count, nil)
	opts.PreflightInventoryPath = "preflight-inventory.json"
	opts.LoadPreflightInventory = func(string, time.Time) (*HAWaveInventoryReceipt, string, error) {
		return inventory, testSHA256("preflight-inventory-artifact"), nil
	}
	return opts
}

func fixedHAWaveClock(now time.Time) func() time.Time {
	return func() time.Time { return now }
}

func writeHAWaveJSON(t *testing.T, name string, value any) string {
	t.Helper()
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertHAWaveBlocker(t *testing.T, blockers []string, wanted string) {
	t.Helper()
	for _, blocker := range blockers {
		if blocker == wanted {
			return
		}
	}
	t.Fatalf("missing blocker %q in %v", wanted, blockers)
}
