// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package iam

import "time"

func edgeSupportCases(now time.Time, policy *Policy) []VerifyBlocker {
	return []VerifyBlocker{
		verifyDenied("support_ticket_required", ErrTicketRequired, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "support-user"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-support-ticket", "support without ticket"), SupportGrantRef: "support-grant-a"}),
		verifyDenied("support_reason_required", ErrReasonRequired, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "support-user"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: RequestContext{CorrelationID: "corr-support-reason", TicketRef: "SUP-1000", Now: now}, SupportGrantRef: "support-grant-a"}),
		verifyDenied("support_grant_expired", ErrSupportGrant, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "support-user"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: RequestContext{CorrelationID: "corr-support-expired", Reason: "tenant requested expired diagnostics", TicketRef: "SUP-1002", Now: now}, SupportGrantRef: "support-grant-expired-a"}),
		verifyDenied("support_principal_required", ErrSupportGrant, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "owner-a"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: RequestContext{CorrelationID: "corr-support-principal", Reason: "tenant requested owner diagnostics", TicketRef: "SUP-1001", Now: now}, SupportGrantRef: "support-grant-owner-a"}),
		verifyDenied("support_grant_absent", ErrSupportGrant, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "support-user"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: RequestContext{CorrelationID: "corr-support-absent", Reason: "tenant requested missing grant diagnostics", TicketRef: "SUP-404", Now: now}, SupportGrantRef: "support-grant-missing"}),
		verifyDenied("support_grant_subject_mismatch", ErrSupportGrant, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "support-shadow"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: RequestContext{CorrelationID: "corr-support-subject", Reason: "tenant requested diagnostics", TicketRef: "SUP-1000", Now: now}, SupportGrantRef: "support-grant-a"}),
		verifyDenied("support_grant_action_denied", ErrSupportGrant, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "support-user"}, Action: ActionProjectWrite, Target: verifierTarget("project-a"), Context: RequestContext{CorrelationID: "corr-support-action", Reason: "tenant requested diagnostics", TicketRef: "SUP-1000", Now: now}, SupportGrantRef: "support-grant-a"}),
		verifyDenied("support_grant_tenant_mismatch", ErrCrossTenant, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "support-user"}, Action: ActionProjectRead, Target: verifierTargetFor("org-b", "tenant-b", "project-b"), Context: RequestContext{CorrelationID: "corr-support-tenant", Reason: "tenant requested diagnostics", TicketRef: "SUP-1000", Now: now}, SupportGrantRef: "support-grant-a"}),
	}
}

func edgeInputCases(now time.Time, policy *Policy) []VerifyBlocker {
	return []VerifyBlocker{
		verifyScenarioInputDenied("malformed_scenario", Scenario("unknown")),
		verifyScenarioInputDenied("stdout_control_character_denied", Scenario("bad\ncloudring_iam_contract_ok")),
		verifyDenied("malformed_input_audited_no_claims", ErrUnknownPrincipal, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "unknown\ncloudring_iam_contract_ok"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-malformed-input", "malformed principal rejected")}),
	}
}

func verifyScenarioInputDenied(id string, scenario Scenario) VerifyBlocker {
	report, code, err := VerifyContract(VerifyOptions{Scenario: scenario})
	if err != nil {
		return VerifyBlocker{ID: id, Message: "scenario verifier error", Expected: "deny", Observed: "error", PolicyRule: "fail_closed", Audited: true, Err: err, Executable: true}
	}
	if code == 2 && report.Status == StatusBlocked && !report.ReadinessClaimed && len(report.Blockers) == 1 && report.Blockers[0].ID == "malformed_scenario" {
		return VerifyBlocker{ID: id, Message: "scenario rejected", Expected: "deny", Observed: "deny", PolicyRule: "fail_closed", Audited: true, Executable: true}
	}
	return VerifyBlocker{ID: id, Message: "scenario was not rejected", Expected: "deny", Observed: "allow", PolicyRule: "fail_closed", Audited: true, Executable: true}
}
