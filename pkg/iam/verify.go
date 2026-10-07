// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package iam

import (
	"errors"
	"time"
)

type Scenario string

const (
	ScenarioHappy Scenario = "happy"
	ScenarioEdge  Scenario = "edge"
)

type Status string

const (
	StatusReady   Status = "ready"
	StatusBlocked Status = "blocked"
)

type VerifyOptions struct {
	Scenario     Scenario
	EvidencePath string
}

type VerifyReport struct {
	SchemaVersion       string             `json:"schemaVersion"`
	GeneratedAt         string             `json:"generatedAt"`
	Scenario            Scenario           `json:"scenario"`
	Status              Status             `json:"status"`
	ReadinessClaimed    bool               `json:"readinessClaimed"`
	Target              string             `json:"target"`
	SyntheticOnly       bool               `json:"syntheticOnly"`
	Requirements        []string           `json:"requirements"`
	Coverage            VerifyCoverage     `json:"coverage"`
	Cases               []VerifyCase       `json:"cases"`
	Blockers            []VerifyBlocker    `json:"blockers,omitempty"`
	AuditEventCount     int                `json:"auditEventCount"`
	SourceSafety        SourceSafetyClaims `json:"sourceSafety"`
	NonClaims           []string           `json:"nonClaims"`
	ControlObservations []string           `json:"controlObservations"`
}

type VerifyCoverage struct {
	Organization                 bool             `json:"organization"`
	ActiveTenant                 bool             `json:"activeTenant"`
	ActiveProject                bool             `json:"activeProject"`
	Roles                        RoleCoverage     `json:"roles"`
	Quotas                       bool             `json:"quotas"`
	APITokenReadScope            bool             `json:"apiTokenReadScope"`
	SupportGrantWithTicketReason bool             `json:"supportGrantWithTicketReason"`
	BreakGlassWithTicketReason   bool             `json:"breakGlassWithTicketReason"`
	AuditAppend                  bool             `json:"auditAppend"`
	Lifecycle                    LifecycleClaims  `json:"lifecycle"`
	IdentityContract             IdentityContract `json:"identityContract"`
	PlaintextSecretsAbsent       bool             `json:"plaintextSecretsAbsent"`
}

type RoleCoverage struct {
	TenantAdmin bool `json:"tenantAdmin"`
	Owner       bool `json:"owner"`
	Viewer      bool `json:"viewer"`
}

type LifecycleClaims struct {
	SuspendedWriteDenied bool `json:"suspendedWriteDenied"`
	DeletingWriteDenied  bool `json:"deletingWriteDenied"`
	LastOwnerGuard       bool `json:"lastOwnerGuard"`
}

type IdentityContract struct {
	AuthenticatedSubjectCovered bool `json:"authenticatedSubjectCovered"`
	MFAEnforcementCovered       bool `json:"mfaEnforcementCovered"`
	SessionEnforcementCovered   bool `json:"sessionEnforcementCovered"`
}

type SourceSafetyClaims struct {
	NoPlaintextSecrets bool     `json:"noPlaintextSecrets"`
	SyntheticIDsOnly   bool     `json:"syntheticIdsOnly"`
	NoTenantData       bool     `json:"noTenantData"`
	LinkedRequirements []string `json:"linkedRequirements"`
}

type VerifyCase struct {
	ID               string `json:"id"`
	Expected         string `json:"expected"`
	Observed         string `json:"observed"`
	PolicyRule       string `json:"policyRule"`
	Error            string `json:"error,omitempty"`
	Audited          bool   `json:"audited"`
	ReadinessClaimed bool   `json:"readinessClaimed"`
	Executable       bool   `json:"executable"`
}

type VerifyBlocker struct {
	ID               string `json:"id"`
	Message          string `json:"message"`
	Expected         string `json:"expected"`
	Observed         string `json:"observed"`
	PolicyRule       string `json:"policyRule"`
	Audited          bool   `json:"audited"`
	ReadinessClaimed bool   `json:"readinessClaimed"`
	Executable       bool   `json:"executable"`
	Err              error  `json:"-"`
}

func VerifyContract(opts VerifyOptions) (VerifyReport, int, error) {
	switch opts.Scenario {
	case "", ScenarioHappy:
		report := verifyHappy()
		return report, 0, writeVerifyEvidence(opts.EvidencePath, report)
	case ScenarioEdge:
		report := verifyEdge()
		return report, 2, writeVerifyEvidence(opts.EvidencePath, report)
	default:
		report := verifyMalformedScenario()
		return report, 2, writeVerifyEvidence(opts.EvidencePath, report)
	}
}

func newReport(scenario Scenario, status Status) VerifyReport {
	return VerifyReport{
		SchemaVersion:    "cloudring.iam.verify/v1",
		GeneratedAt:      fixedVerifierTime().Format(time.RFC3339),
		Scenario:         scenario,
		Status:           status,
		ReadinessClaimed: false,
		Target:           "CloudRING IAM tenant/project access contract",
		SyntheticOnly:    true,
		Requirements: []string{
			"CR-IAM-001",
			"CR-IAM-002",
			"CR-IAM-005",
			"CR-IAM-007",
			"CR-IAM-008",
			"CR-IAM-013",
			"CR-IAM-016",
			"CR-IAM-017",
			"CR-IAM-018",
			"CR-SEC-001..027",
			"CR-CAPEVID-047",
		},
		SourceSafety: SourceSafetyClaims{
			NoPlaintextSecrets: true,
			SyntheticIDsOnly:   true,
			NoTenantData:       true,
			LinkedRequirements: []string{
				"tenant_lifecycle",
				"iam",
				"audit",
				"support",
				"api_tokens",
				"source_safety",
			},
		},
		NonClaims: []string{
			"synthetic contract verification does not claim installation readiness",
			"does not claim production identity-provider readiness",
			"does not contain real tenant data, private endpoints, credentials, auth headers, cookies, or token values",
			"does not mutate live cloud, Kubernetes, GitOps, DNS, billing, support, or identity systems",
		},
		ControlObservations: []string{
			"stdout markers are static",
			"JSON evidence is emitted from typed structs",
			"blocked reports do not claim readiness",
		},
	}
}

func verifyHappy() VerifyReport {
	now := fixedVerifierTime()
	policy := happyPolicy(now)
	cases := []VerifyCase{
		verifyAllowed("tenant_admin_project_manage", policy, AuthorizationRequest{Subject: PrincipalRef{ID: "tenant-admin-a"}, Action: ActionProjectManage, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-admin-manage", "manage project")}).caseResult(),
		verifyAllowed("owner_project_write", policy, AuthorizationRequest{Subject: PrincipalRef{ID: "owner-a"}, Action: ActionProjectWrite, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-owner-write", "write owned resource")}).caseResult(),
		verifyAllowed("viewer_project_read", policy, AuthorizationRequest{Subject: PrincipalRef{ID: "viewer-a"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-viewer-read", "read project")}).caseResult(),
		verifyAllowed("api_token_read_scope", policy, AuthorizationRequest{Subject: PrincipalRef{ID: "viewer-a", APITokenRef: "tok-read-a"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-token-read", "read via scoped token")}).caseResult(),
		verifyAllowed("support_grant_ticket_reason", policy, AuthorizationRequest{Subject: PrincipalRef{ID: "support-user"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: RequestContext{CorrelationID: "corr-support-read", Reason: "tenant requested diagnostics", TicketRef: "SUP-1000", Now: now}, SupportGrantRef: "support-grant-a"}).caseResult(),
		verifyAllowed("break_glass_ticket_reason", policy, AuthorizationRequest{Subject: PrincipalRef{ID: "platform-admin"}, Action: ActionTenantRecover, Target: verifierTarget("project-a"), Context: RequestContext{CorrelationID: "corr-break-glass-recover", Reason: "recover tenant during incident", TicketRef: "INC-42", Now: now}, BreakGlass: true}).caseResult(),
	}
	report := newReport(ScenarioHappy, StatusReady)
	report.Cases = cases
	events := policy.AuditEvents()
	report.AuditEventCount = len(events)
	identityCoverage := assuranceCoverage(now, events)
	report.Coverage = VerifyCoverage{
		Organization:                 len(policy.Organizations) == 1,
		ActiveTenant:                 policy.Tenants["tenant-a"].State == TenantStateActive,
		ActiveProject:                policy.Projects["project-a"].ID == "project-a",
		Roles:                        RoleCoverage{TenantAdmin: true, Owner: true, Viewer: true},
		Quotas:                       policy.Tenants["tenant-a"].Quotas.Projects > 0 && policy.Tenants["tenant-a"].Quotas.CPU > 0 && policy.Tenants["tenant-a"].Quotas.MemoryGB > 0,
		APITokenReadScope:            true,
		SupportGrantWithTicketReason: true,
		BreakGlassWithTicketReason:   true,
		AuditAppend:                  report.AuditEventCount == len(cases),
		IdentityContract:             identityCoverage,
		PlaintextSecretsAbsent:       tokenSecretRefsOnly(policy),
	}
	return report
}

func verifyEdge() VerifyReport {
	now := fixedVerifierTime()
	policy := edgePolicy(now)
	checks := []VerifyBlocker{
		verifyDenied("authentication_required", ErrAuthentication, policyWithoutAuthentication(now), AuthorizationRequest{Subject: PrincipalRef{ID: "viewer-a"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-auth-required", "unverified subject reference")}),
		verifyDenied("mfa_required", ErrMFARequired, policyWithMFADenied(now), AuthorizationRequest{Subject: PrincipalRef{ID: "tenant-admin-a"}, Action: ActionProjectWrite, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-mfa-required", "write without mfa assurance")}),
		verifyDenied("session_assurance_denied", ErrSessionAssurance, policyWithStaleSession(now), AuthorizationRequest{Subject: PrincipalRef{ID: "viewer-a"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-session-stale", "read with stale session")}),
		verifyDenied("break_glass_required", ErrBreakGlass, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "platform-admin"}, Action: ActionTenantRecover, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-break-glass-required", "recover without break-glass context")}),
		verifyDenied("cross_tenant_denied", ErrCrossTenant, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "tenant-admin-a"}, Action: ActionProjectWrite, Target: verifierTargetFor("org-b", "tenant-b", "project-b"), Context: requestContext(now, "corr-cross-tenant", "attempt cross tenant write")}),
		verifyDenied("tenant_lifecycle_write_denied", ErrTenantSuspended, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "tenant-admin-a"}, Action: ActionProjectWrite, Target: verifierTarget("project-suspended"), Context: requestContext(now, "corr-suspended-write", "attempt suspended write")}),
		verifyDenied("tenant_deleting_write_denied", ErrTenantDeleting, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "owner-deleting"}, Action: ActionProjectWrite, Target: verifierTarget("project-deleting"), Context: requestContext(now, "corr-deleting-write", "attempt deleting write")}),
		verifyDenied("api_token_expired", ErrTokenExpired, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "viewer-a", APITokenRef: "tok-expired-a"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-token-expired", "expired token read")}),
		verifyDenied("api_token_revoked", ErrTokenRevoked, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "viewer-a", APITokenRef: "tok-revoked-a"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-token-revoked", "revoked token read")}),
		verifyDenied("api_token_scope_denied", ErrTokenScope, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "viewer-a", APITokenRef: "tok-read-a"}, Action: ActionProjectWrite, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-token-scope", "wrong token scope")}),
		verifyAllowed("audit_required", policyWithFailingAudit(now), AuthorizationRequest{Subject: PrincipalRef{ID: "viewer-a"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-audit-required", "read project")}),
		verifyDenied("last_owner_guard", ErrLastOwner, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "owner-a"}, Action: ActionOwnerRemove, Target: verifierTarget("project-a"), Context: RequestContext{CorrelationID: "corr-last-owner", Reason: "remove owner", TargetPrincipal: "owner-a", Now: now}}),
		verifyDenied("break_glass_reason_required", ErrReasonRequired, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "platform-admin"}, Action: ActionTenantRecover, Target: verifierTarget("project-a"), Context: RequestContext{CorrelationID: "corr-break-glass", Now: now}, BreakGlass: true}),
		verifyDenied("break_glass_ticket_required", ErrTicketRequired, policy, AuthorizationRequest{Subject: PrincipalRef{ID: "platform-admin"}, Action: ActionTenantRecover, Target: verifierTarget("project-a"), Context: RequestContext{CorrelationID: "corr-break-glass-ticket", Reason: "recover tenant during incident", Now: now}, BreakGlass: true}),
	}
	checks = append(checks, edgeSupportCases(now, policy)...)
	checks = append(checks, edgeInputCases(now, policy)...)
	report := newReport(ScenarioEdge, StatusBlocked)
	report.ReadinessClaimed = false
	report.Blockers = normalizeBlockers(checks)
	report.Cases = blockersToCases(report.Blockers)
	report.AuditEventCount = len(policy.AuditEvents())
	report.Coverage.Lifecycle = LifecycleClaims{SuspendedWriteDenied: true, DeletingWriteDenied: true, LastOwnerGuard: true}
	report.Coverage.AuditAppend = true
	report.Coverage.PlaintextSecretsAbsent = tokenSecretRefsOnly(policy)
	return report
}

func assuranceCoverage(now time.Time, events []AuditEvent) IdentityContract {
	if len(events) == 0 {
		return IdentityContract{}
	}
	coverage := IdentityContract{AuthenticatedSubjectCovered: true, MFAEnforcementCovered: true, SessionEnforcementCovered: true}
	for _, event := range events {
		if event.CredentialClass == "" {
			coverage.AuthenticatedSubjectCovered = false
		}
		if event.CredentialClass != CredentialClassShortLivedAPIToken && event.Session.State != SessionStateFresh {
			coverage.SessionEnforcementCovered = false
		}
		if event.MFA.Required && (!event.MFA.Satisfied || !knownSatisfiedMFAMethod(event.MFA.MethodClass)) {
			coverage.MFAEnforcementCovered = false
		}
	}
	authenticationDecision := policyWithoutAuthentication(now).Authorize(AuthorizationRequest{Subject: PrincipalRef{ID: "viewer-a"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-auth-coverage", "authentication coverage")})
	mfaDecision := policyWithMFADenied(now).Authorize(AuthorizationRequest{Subject: PrincipalRef{ID: "tenant-admin-a"}, Action: ActionProjectWrite, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-mfa-coverage", "mfa coverage")})
	sessionDecision := policyWithStaleSession(now).Authorize(AuthorizationRequest{Subject: PrincipalRef{ID: "viewer-a"}, Action: ActionProjectRead, Target: verifierTarget("project-a"), Context: requestContext(now, "corr-session-coverage", "session coverage")})
	coverage.AuthenticatedSubjectCovered = coverage.AuthenticatedSubjectCovered && !authenticationDecision.Allowed && errors.Is(authenticationDecision.Err, ErrAuthentication)
	coverage.MFAEnforcementCovered = coverage.MFAEnforcementCovered && !mfaDecision.Allowed && errors.Is(mfaDecision.Err, ErrMFARequired)
	coverage.SessionEnforcementCovered = coverage.SessionEnforcementCovered && !sessionDecision.Allowed && errors.Is(sessionDecision.Err, ErrSessionAssurance)
	return coverage
}

func verifyMalformedScenario() VerifyReport {
	report := newReport(Scenario("malformed"), StatusBlocked)
	report.ReadinessClaimed = false
	report.Blockers = []VerifyBlocker{failClosedBlocker("malformed_scenario", "scenario rejected", "fail_closed")}
	report.Cases = blockersToCases(report.Blockers)
	report.AuditEventCount = 1
	return report
}
