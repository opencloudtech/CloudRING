// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package iam

import (
	"context"
	"time"
)

func fixedVerifierTime() time.Time {
	return time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
}

// syntheticContractAuthenticationVerifier exists only to exercise the
// non-serving Verify contract. It echoes fixture request references and must
// never be used as a serving authenticator.
func syntheticContractAuthenticationVerifier() AuthenticationVerifier {
	return AuthenticationFunc(func(_ context.Context, request AuthorizationRequest, at time.Time) (AuthenticationResult, error) {
		result := AuthenticationResult{
			SubjectID:       request.Subject.ID,
			CredentialClass: CredentialClassInteractiveSession,
			MFA:             MFAAssurance{Required: true, Satisfied: true, MethodClass: MFAMethodExternalIDP},
			Session:         SessionAssurance{State: SessionStateFresh, MaxAgeSeconds: 3600},
			Proof:           AuthenticationProof{VerifiedAt: at, ExpiresAt: at.Add(time.Hour)},
		}
		switch {
		case request.Subject.APITokenRef != "":
			result.APITokenRef = request.Subject.APITokenRef
			result.CredentialClass = CredentialClassShortLivedAPIToken
			result.MFA = MFAAssurance{MethodClass: MFAMethodNone}
			result.Session = SessionAssurance{State: SessionStateAbsent}
		case request.BreakGlass:
			result.CredentialClass = CredentialClassBreakGlass
		case request.SupportGrantRef != "":
			result.CredentialClass = CredentialClassSupportGrant
		}
		return result, nil
	})
}

func happyPolicy(now time.Time) *Policy {
	policy := NewPolicy(PolicyConfig{
		Clock:                         FixedClock{At: now},
		AuditSink:                     NewMemoryAuditSink(),
		AuthenticationVerifier:        syntheticContractAuthenticationVerifier(),
		AuthenticationProofMaxAge:     time.Hour,
		AuthenticationProofFutureSkew: time.Minute,
		AllowEphemeralAudit:           true,
	})
	policy.Organizations["org-a"] = Organization{ID: "org-a", Name: "Synthetic Organization A"}
	policy.Tenants["tenant-a"] = Tenant{
		ID:    "tenant-a",
		OrgID: "org-a",
		State: TenantStateActive,
		Quotas: Quotas{
			Projects: 8,
			CPU:      64,
			MemoryGB: 256,
		},
	}
	policy.Projects["project-a"] = Project{
		ID:        "project-a",
		TenantID:  "tenant-a",
		OrgID:     "org-a",
		Namespace: "tenant-a-system",
		Scopes: []NamespaceScope{
			{Namespace: "tenant-a-readonly", Actions: []Action{ActionProjectRead}},
		},
	}
	policy.Principals["tenant-admin-a"] = Principal{
		ID: "tenant-admin-a",
		Memberships: []Membership{
			{OrgID: "org-a", TenantID: "tenant-a", ProjectID: "project-a", Role: RoleTenantAdmin},
		},
	}
	policy.Principals["owner-a"] = Principal{
		ID: "owner-a",
		Memberships: []Membership{
			{OrgID: "org-a", TenantID: "tenant-a", ProjectID: "project-a", Role: RoleOwner},
		},
	}
	policy.Principals["viewer-a"] = Principal{
		ID: "viewer-a",
		Memberships: []Membership{
			{OrgID: "org-a", TenantID: "tenant-a", ProjectID: "project-a", Role: RoleTenantViewer},
		},
	}
	policy.Principals["platform-admin"] = Principal{
		ID: "platform-admin",
		Memberships: []Membership{
			{OrgID: "org-a", TenantID: "tenant-a", Role: RolePlatformAdmin},
		},
	}
	policy.Principals["support-user"] = Principal{ID: "support-user", Support: true}
	policy.Principals["support-shadow"] = Principal{ID: "support-shadow", Support: true}
	policy.APITokens["tok-read-a"] = APIToken{
		Reference:     "tok-read-a",
		SubjectID:     "viewer-a",
		SecretHashRef: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		TenantID:      "tenant-a",
		ProjectID:     "project-a",
		Scopes:        []Action{ActionProjectRead},
		ExpiresAt:     now.Add(4 * time.Hour),
	}
	policy.SupportGrants["support-grant-a"] = SupportGrant{
		Reference: "support-grant-a",
		SubjectID: "support-user",
		TenantID:  "tenant-a",
		ProjectID: "project-a",
		Actions:   []Action{ActionProjectRead},
		TicketRef: "SUP-1000",
		Reason:    "tenant requested diagnostics",
		ExpiresAt: now.Add(time.Hour),
	}
	policy.SupportGrants["support-grant-owner-a"] = SupportGrant{
		Reference: "support-grant-owner-a",
		SubjectID: "owner-a",
		TenantID:  "tenant-a",
		ProjectID: "project-a",
		Actions:   []Action{ActionProjectRead},
		TicketRef: "SUP-1001",
		Reason:    "tenant requested owner diagnostics",
		ExpiresAt: now.Add(time.Hour),
	}
	policy.SupportGrants["support-grant-expired-a"] = SupportGrant{
		Reference: "support-grant-expired-a",
		SubjectID: "support-user",
		TenantID:  "tenant-a",
		ProjectID: "project-a",
		Actions:   []Action{ActionProjectRead},
		TicketRef: "SUP-1002",
		Reason:    "tenant requested expired diagnostics",
		ExpiresAt: now.Add(-time.Minute),
	}
	return policy
}

func edgePolicy(now time.Time) *Policy {
	policy := happyPolicy(now)
	policy.Organizations["org-b"] = Organization{ID: "org-b", Name: "Synthetic Organization B"}
	policy.Tenants["tenant-b"] = Tenant{ID: "tenant-b", OrgID: "org-b", State: TenantStateActive}
	policy.Tenants["tenant-suspended"] = Tenant{ID: "tenant-suspended", OrgID: "org-a", State: TenantStateSuspended}
	policy.Tenants["tenant-deleting"] = Tenant{ID: "tenant-deleting", OrgID: "org-a", State: TenantStateDeleting}
	policy.Projects["project-b"] = Project{ID: "project-b", TenantID: "tenant-b", OrgID: "org-b", Namespace: "tenant-b-system"}
	policy.Projects["project-suspended"] = Project{ID: "project-suspended", TenantID: "tenant-suspended", OrgID: "org-a", Namespace: "tenant-suspended-system"}
	policy.Projects["project-deleting"] = Project{ID: "project-deleting", TenantID: "tenant-deleting", OrgID: "org-a", Namespace: "tenant-deleting-system"}
	policy.Principals["owner-deleting"] = Principal{
		ID: "owner-deleting",
		Memberships: []Membership{
			{OrgID: "org-a", TenantID: "tenant-deleting", ProjectID: "project-deleting", Role: RoleOwner},
		},
	}
	policy.APITokens["tok-expired-a"] = APIToken{
		Reference:     "tok-expired-a",
		SubjectID:     "viewer-a",
		SecretHashRef: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		TenantID:      "tenant-a",
		ProjectID:     "project-a",
		Scopes:        []Action{ActionProjectRead},
		ExpiresAt:     now.Add(-time.Minute),
	}
	policy.APITokens["tok-revoked-a"] = APIToken{
		Reference:     "tok-revoked-a",
		SubjectID:     "viewer-a",
		SecretHashRef: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		TenantID:      "tenant-a",
		ProjectID:     "project-a",
		Scopes:        []Action{ActionProjectRead},
		ExpiresAt:     now.Add(time.Hour),
		RevokedAt:     now.Add(-time.Minute),
	}
	return policy
}

func policyWithFailingAudit(now time.Time) *Policy {
	policy := happyPolicy(now)
	policy.AuditSink = FailingAuditSink{}
	return policy
}

func policyWithoutAuthentication(now time.Time) *Policy {
	policy := edgePolicy(now)
	policy.authenticator = nil
	return policy
}

func policyWithMFADenied(now time.Time) *Policy {
	policy := edgePolicy(now)
	policy.authenticator = AuthenticationFunc(func(ctx context.Context, request AuthorizationRequest, _ time.Time) (AuthenticationResult, error) {
		result, _ := syntheticContractAuthenticationVerifier().Authenticate(ctx, request, now)
		result.MFA.Satisfied = false
		return result, nil
	})
	return policy
}

func policyWithStaleSession(now time.Time) *Policy {
	policy := edgePolicy(now)
	policy.authenticator = AuthenticationFunc(func(ctx context.Context, request AuthorizationRequest, _ time.Time) (AuthenticationResult, error) {
		result, _ := syntheticContractAuthenticationVerifier().Authenticate(ctx, request, now)
		result.Session.State = SessionStateStale
		return result, nil
	})
	return policy
}

func verifierTarget(projectID string) TargetRef {
	switch projectID {
	case "project-suspended":
		return verifierTargetFor("org-a", "tenant-suspended", projectID)
	case "project-deleting":
		return verifierTargetFor("org-a", "tenant-deleting", projectID)
	default:
		return verifierTargetFor("org-a", "tenant-a", projectID)
	}
}

func verifierTargetFor(orgID string, tenantID string, projectID string) TargetRef {
	return TargetRef{
		OrgID:     orgID,
		TenantID:  tenantID,
		ProjectID: projectID,
		Namespace: tenantID + "-system",
		Resource:  "project",
		Name:      projectID,
	}
}

func requestContext(now time.Time, correlationID string, reason string) RequestContext {
	return RequestContext{CorrelationID: correlationID, Reason: reason, Now: now}
}
