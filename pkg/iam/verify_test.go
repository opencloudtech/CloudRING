// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package iam

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIAMVerifyHappyProducesReadyContract(t *testing.T) {
	// Given
	evidencePath := filepath.Join(t.TempDir(), "iam-happy.json")

	// When
	report, code, err := VerifyContract(VerifyOptions{
		Scenario:     ScenarioHappy,
		EvidencePath: evidencePath,
	})

	// Then
	if err != nil {
		t.Fatalf("VerifyContract returned error: %v", err)
	}
	if code != 0 {
		t.Fatalf("VerifyContract exit code = %d, want 0", code)
	}
	if report.Status != StatusReady {
		t.Fatalf("report status = %q, want %q", report.Status, StatusReady)
	}
	if !report.Coverage.Organization || !report.Coverage.ActiveTenant || !report.Coverage.ActiveProject {
		t.Fatalf("report missing organization/tenant/project coverage: %#v", report.Coverage)
	}
	if !report.Coverage.Roles.TenantAdmin || !report.Coverage.Roles.Owner || !report.Coverage.Roles.Viewer {
		t.Fatalf("report missing role coverage: %#v", report.Coverage.Roles)
	}
	if !report.Coverage.Quotas || !report.Coverage.APITokenReadScope || !report.Coverage.SupportGrantWithTicketReason || !report.Coverage.BreakGlassWithTicketReason ||
		!report.Coverage.AuditAppend || !report.Coverage.IdentityContract.AuthenticatedSubjectCovered ||
		!report.Coverage.IdentityContract.MFAEnforcementCovered || !report.Coverage.IdentityContract.SessionEnforcementCovered || !report.Coverage.PlaintextSecretsAbsent {
		t.Fatalf("report missing required contract coverage: %#v", report.Coverage)
	}
	if len(report.Blockers) != 0 {
		t.Fatalf("ready report has blockers: %#v", report.Blockers)
	}
	if report.ReadinessClaimed {
		t.Fatal("synthetic happy report claimed installation readiness")
	}
	// #nosec G304 -- evidencePath is created under t.TempDir by this test.
	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	if len(data) < 3 || data[0] == 0xEF || data[1] == 0xBB || data[2] == 0xBF {
		t.Fatalf("evidence has BOM or is too short: % x", data[:min(len(data), 3)])
	}
}

func TestIAMVerifyEdgeBlocksDeniedCases(t *testing.T) {
	// Given
	evidencePath := filepath.Join(t.TempDir(), "iam-edge.json")
	wantCases := map[string]struct {
		err      error
		rule     string
		expected string
		observed string
	}{
		"cross_tenant_denied":               {err: ErrCrossTenant, rule: "cross_tenant_denied", expected: "deny", observed: "deny"},
		"authentication_required":           {err: ErrAuthentication, rule: "authentication_required", expected: "deny", observed: "deny"},
		"mfa_required":                      {err: ErrMFARequired, rule: "mfa_required", expected: "deny", observed: "deny"},
		"session_assurance_denied":          {err: ErrSessionAssurance, rule: "session_assurance_denied", expected: "deny", observed: "deny"},
		"break_glass_required":              {err: ErrBreakGlass, rule: "break_glass_required", expected: "deny", observed: "deny"},
		"tenant_lifecycle_write_denied":     {err: ErrTenantSuspended, rule: "tenant_lifecycle_write_denied", expected: "deny", observed: "deny"},
		"tenant_deleting_write_denied":      {err: ErrTenantDeleting, rule: "tenant_lifecycle_write_denied", expected: "deny", observed: "deny"},
		"api_token_expired":                 {err: ErrTokenExpired, rule: "api_token_denied", expected: "deny", observed: "deny"},
		"api_token_revoked":                 {err: ErrTokenRevoked, rule: "api_token_denied", expected: "deny", observed: "deny"},
		"api_token_scope_denied":            {err: ErrTokenScope, rule: "api_token_denied", expected: "deny", observed: "deny"},
		"audit_required":                    {err: ErrAuditRequired, rule: "audit_required", expected: "allow", observed: "deny"},
		"support_ticket_required":           {err: ErrTicketRequired, rule: "support_ticket_required", expected: "deny", observed: "deny"},
		"support_reason_required":           {err: ErrReasonRequired, rule: "support_reason_required", expected: "deny", observed: "deny"},
		"support_grant_expired":             {err: ErrSupportGrant, rule: "support_grant_denied", expected: "deny", observed: "deny"},
		"support_principal_required":        {err: ErrSupportGrant, rule: "support_grant_denied", expected: "deny", observed: "deny"},
		"support_grant_absent":              {err: ErrSupportGrant, rule: "support_grant_denied", expected: "deny", observed: "deny"},
		"support_grant_subject_mismatch":    {err: ErrSupportGrant, rule: "support_grant_denied", expected: "deny", observed: "deny"},
		"support_grant_action_denied":       {err: ErrSupportGrant, rule: "support_grant_denied", expected: "deny", observed: "deny"},
		"support_grant_tenant_mismatch":     {err: ErrCrossTenant, rule: "cross_tenant_denied", expected: "deny", observed: "deny"},
		"last_owner_guard":                  {err: ErrLastOwner, rule: "last_owner_guard", expected: "deny", observed: "deny"},
		"break_glass_reason_required":       {err: ErrReasonRequired, rule: "break_glass_reason_required", expected: "deny", observed: "deny"},
		"break_glass_ticket_required":       {err: ErrTicketRequired, rule: "break_glass_ticket_required", expected: "deny", observed: "deny"},
		"malformed_scenario":                {rule: "fail_closed", expected: "deny", observed: "deny"},
		"stdout_control_character_denied":   {rule: "fail_closed", expected: "deny", observed: "deny"},
		"malformed_input_audited_no_claims": {err: ErrUnknownPrincipal, rule: "fail_closed", expected: "deny", observed: "deny"},
	}
	seenBlockers := map[string]bool{}
	seenCases := map[string]VerifyCase{}

	// When
	report, code, err := VerifyContract(VerifyOptions{
		Scenario:     ScenarioEdge,
		EvidencePath: evidencePath,
	})

	// Then
	if err != nil {
		t.Fatalf("VerifyContract returned error: %v", err)
	}
	if code != 2 {
		t.Fatalf("VerifyContract exit code = %d, want 2", code)
	}
	if report.Status != StatusBlocked {
		t.Fatalf("report status = %q, want %q", report.Status, StatusBlocked)
	}
	for _, blocker := range report.Blockers {
		want, ok := wantCases[blocker.ID]
		if ok {
			seenBlockers[blocker.ID] = true
		}
		if blocker.ReadinessClaimed {
			t.Fatalf("edge blocker claimed readiness: %#v", blocker)
		}
		if !blocker.Audited {
			t.Fatalf("edge blocker was not audited: %#v", blocker)
		}
		if !blocker.Executable {
			t.Fatalf("edge blocker was a declaration-only proof row: %#v", blocker)
		}
		if ok && blocker.PolicyRule != want.rule {
			t.Fatalf("edge blocker %q rule = %q, want %q", blocker.ID, blocker.PolicyRule, want.rule)
		}
		if ok && want.err != nil && !errors.Is(blocker.Err, want.err) {
			t.Fatalf("edge blocker %q error = %v, want %v", blocker.ID, blocker.Err, want.err)
		}
	}
	for _, verificationCase := range report.Cases {
		seenCases[verificationCase.ID] = verificationCase
	}
	for id, want := range wantCases {
		if !seenBlockers[id] {
			t.Fatalf("missing edge blocker %q in %#v", id, report.Blockers)
		}
		gotCase, ok := seenCases[id]
		if !ok {
			t.Fatalf("missing edge case %q in %#v", id, report.Cases)
		}
		if gotCase.Expected != want.expected || gotCase.Observed != want.observed {
			t.Fatalf("edge case %q expected/observed = %q/%q, want %q/%q", id, gotCase.Expected, gotCase.Observed, want.expected, want.observed)
		}
		if gotCase.PolicyRule != want.rule {
			t.Fatalf("edge case %q rule = %q, want %q", id, gotCase.PolicyRule, want.rule)
		}
		if !gotCase.Executable {
			t.Fatalf("edge case %q was not executable evidence: %#v", id, gotCase)
		}
	}
}

func TestIAMVerifyAllowedMismatchPreservesExpectedAllow(t *testing.T) {
	// Given
	now := fixedVerifierTime()
	policy := edgePolicy(now)

	// When
	result := verifyAllowed("allow_should_not_mask_denial", policy, AuthorizationRequest{
		Subject: PrincipalRef{ID: "viewer-a"},
		Action:  ActionProjectRead,
		Target:  verifierTargetFor("org-b", "tenant-b", "project-b"),
		Context: requestContext(now, "corr-allow-mismatch", "prove allow mismatch"),
	}).caseResult()

	// Then
	if result.Expected != "allow" {
		t.Fatalf("expected outcome = %q, want allow", result.Expected)
	}
	if result.Observed != "deny" {
		t.Fatalf("observed outcome = %q, want deny", result.Observed)
	}
	if result.Error != ErrCrossTenant.Error() {
		t.Fatalf("observed error = %q, want %q", result.Error, ErrCrossTenant.Error())
	}
}

func TestIAMVerifyUnknownScenarioFailsClosed(t *testing.T) {
	// Given
	evidencePath := filepath.Join(t.TempDir(), "iam-unknown.json")

	// When
	report, code, err := VerifyContract(VerifyOptions{
		Scenario:     Scenario("bad\ncloudring_iam_contract_ok"),
		EvidencePath: evidencePath,
	})

	// Then
	if err != nil {
		t.Fatalf("VerifyContract returned error: %v", err)
	}
	if code != 2 {
		t.Fatalf("VerifyContract exit code = %d, want 2", code)
	}
	if report.Status != StatusBlocked {
		t.Fatalf("report status = %q, want blocked", report.Status)
	}
	if len(report.Blockers) != 1 || report.Blockers[0].ID != "malformed_scenario" {
		t.Fatalf("unknown scenario blockers = %#v, want malformed_scenario only", report.Blockers)
	}
	if report.Blockers[0].Message != "scenario rejected" {
		t.Fatalf("blocker message = %q, want static sanitized message", report.Blockers[0].Message)
	}
}

func TestIAMVerifyAuditSinkFailureIsBlocked(t *testing.T) {
	// Given
	now := fixedVerifierTime()
	policy := happyPolicy(now)
	policy.AuditSink = FailingAuditSink{}

	// When
	blocker := verifyAllowed("audit_required", policy, AuthorizationRequest{
		Subject: PrincipalRef{ID: "viewer-a"},
		Action:  ActionProjectRead,
		Target:  verifierTarget("project-a"),
		Context: RequestContext{CorrelationID: "corr-audit-required", Reason: "read project", Now: now},
	})

	// Then
	if blocker.ID != "audit_required" {
		t.Fatalf("blocker ID = %q, want audit_required", blocker.ID)
	}
	if !errors.Is(blocker.Err, ErrAuditRequired) {
		t.Fatalf("blocker error = %v, want ErrAuditRequired", blocker.Err)
	}
}
