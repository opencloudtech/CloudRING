// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package iam

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSubjectReferenceWithoutTrustedAuthenticationIsDenied(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	policy.authenticator = nil

	decision := policy.Authorize(AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin", APITokenRef: "tok-project-a"},
		Action:  ActionProjectRead,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{CorrelationID: "corr-unverified-reference", Reason: "unverified reference"},
	})

	if decision.Allowed || !errors.Is(decision.Err, ErrAuthentication) {
		t.Fatalf("Authorize accepted an unverified subject reference: %#v", decision)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionProjectRead, "authentication_required")
}

func TestAuthenticationSubjectMismatchIsDenied(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	policy.authenticator = AuthenticationFunc(func(context.Context, AuthorizationRequest, time.Time) (AuthenticationResult, error) {
		return interactiveAuthentication("owner-a", now), nil
	})

	decision := policy.Authorize(AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin"},
		Action:  ActionProjectRead,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{CorrelationID: "corr-subject-mismatch", Reason: "mismatched authentication"},
	})
	if decision.Allowed || !errors.Is(decision.Err, ErrAuthentication) {
		t.Fatalf("Authorize accepted mismatched authentication: %#v", decision)
	}
}

func TestAuthenticationVerifierConsumesOutOfBandContextProof(t *testing.T) {
	type proofKey struct{}
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	policy.authenticator = AuthenticationFunc(func(ctx context.Context, request AuthorizationRequest, _ time.Time) (AuthenticationResult, error) {
		if proved, _ := ctx.Value(proofKey{}).(bool); !proved {
			return AuthenticationResult{}, ErrAuthentication
		}
		return interactiveAuthentication(request.Subject.ID, now), nil
	})
	request := AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin"},
		Action:  ActionProjectRead,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{CorrelationID: "corr-context-proof", Reason: "out-of-band proof"},
	}

	if decision := policy.Authorize(request); decision.Allowed || !errors.Is(decision.Err, ErrAuthentication) {
		t.Fatalf("Authorize accepted a reference without context proof: %#v", decision)
	}
	decision := policy.AuthorizeContext(context.WithValue(context.Background(), proofKey{}, true), request)
	if !decision.Allowed {
		t.Fatalf("AuthorizeContext rejected verified context proof: %#v", decision)
	}
}

func TestMFAAndSessionAssuranceFailClosed(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	tests := []struct {
		name   string
		mutate func(*AuthenticationResult)
		want   error
		rule   string
	}{
		{name: "mfa unsatisfied", mutate: func(result *AuthenticationResult) { result.MFA.Satisfied = false }, want: ErrMFARequired, rule: "mfa_required"},
		{name: "session stale", mutate: func(result *AuthenticationResult) { result.Session.State = SessionStateStale }, want: ErrSessionAssurance, rule: "session_assurance_denied"},
		{name: "session revoked", mutate: func(result *AuthenticationResult) { result.Session.State = SessionStateRevoked }, want: ErrSessionAssurance, rule: "session_assurance_denied"},
		{name: "reauthentication required", mutate: func(result *AuthenticationResult) { result.Session.ReauthenticationRequired = true }, want: ErrSessionAssurance, rule: "session_assurance_denied"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy(now)
			policy.authenticator = AuthenticationFunc(func(_ context.Context, request AuthorizationRequest, _ time.Time) (AuthenticationResult, error) {
				result := interactiveAuthentication(request.Subject.ID, now)
				test.mutate(&result)
				return result, nil
			})
			decision := policy.Authorize(AuthorizationRequest{
				Subject: PrincipalRef{ID: "user-tenant-admin"},
				Action:  ActionProjectWrite,
				Target:  testTarget("org-a", "tenant-a", "project-a"),
				Context: RequestContext{CorrelationID: "corr-assurance-" + test.name, Reason: "assurance negative case"},
			})
			if decision.Allowed || !errors.Is(decision.Err, test.want) {
				t.Fatalf("Authorize accepted %s: %#v", test.name, decision)
			}
			requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionProjectWrite, test.rule)
		})
	}
}

func TestAllowDecisionAuditsAuthenticationAssurance(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	decision := policy.Authorize(AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin"},
		Action:  ActionProjectWrite,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{CorrelationID: "corr-assurance-audit", Reason: "write with assurance"},
	})
	if !decision.Allowed || !decision.MFA.Required || !decision.MFA.Satisfied || decision.Session.State != SessionStateFresh {
		t.Fatalf("allow decision omitted assurance: %#v", decision)
	}
	event := policy.AuditEvents()[0]
	if event.CredentialClass != CredentialClassInteractiveSession || !event.MFA.Required || !event.MFA.Satisfied || event.Session.State != SessionStateFresh {
		t.Fatalf("audit event omitted assurance: %#v", event)
	}
	if event.Proof.VerifiedAt.IsZero() || decision.Proof.VerifiedAt.IsZero() {
		t.Fatalf("trusted proof timestamp was omitted: decision=%#v event=%#v", decision, event)
	}
}

func TestAuthenticationProofFreshnessFailsClosed(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	tests := []struct {
		name   string
		mutate func(*AuthenticationResult)
	}{
		{name: "zero proof", mutate: func(result *AuthenticationResult) { result.Proof = AuthenticationProof{} }},
		{name: "stale proof", mutate: func(result *AuthenticationResult) {
			result.Proof.VerifiedAt = now.Add(-time.Hour - time.Second)
		}},
		{name: "future proof", mutate: func(result *AuthenticationResult) {
			result.Proof.VerifiedAt = now.Add(time.Minute + time.Second)
			result.Proof.ExpiresAt = now.Add(time.Hour)
		}},
		{name: "expired proof", mutate: func(result *AuthenticationResult) {
			result.Proof.VerifiedAt = now.Add(-time.Minute)
			result.Proof.ExpiresAt = now
		}},
		{name: "unbounded session declaration", mutate: func(result *AuthenticationResult) {
			result.Session.MaxAgeSeconds = 3601
		}},
		{name: "session proof too old", mutate: func(result *AuthenticationResult) {
			result.Session.MaxAgeSeconds = 30
			result.Proof.VerifiedAt = now.Add(-31 * time.Second)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy(now)
			policy.authenticator = AuthenticationFunc(func(_ context.Context, request AuthorizationRequest, _ time.Time) (AuthenticationResult, error) {
				result := interactiveAuthentication(request.Subject.ID, now)
				test.mutate(&result)
				return result, nil
			})
			decision := policy.Authorize(AuthorizationRequest{
				Subject: PrincipalRef{ID: "user-tenant-admin"},
				Action:  ActionProjectRead,
				Target:  testTarget("org-a", "tenant-a", "project-a"),
				Context: RequestContext{
					CorrelationID: "corr-proof-" + test.name,
					Reason:        "proof freshness negative case",
					Now:           now.Add(-24 * time.Hour),
				},
			})
			if decision.Allowed || !errors.Is(decision.Err, ErrAuthentication) {
				t.Fatalf("Authorize accepted %s: %#v", test.name, decision)
			}
			requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionProjectRead, "authentication_required")
		})
	}
}

func TestAuthenticationProofFreshnessBoundariesAreInclusive(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	for name, verifiedAt := range map[string]time.Time{
		"maximum age": now.Add(-time.Hour),
		"future skew": now.Add(time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			policy := testPolicy(now)
			policy.authenticator = AuthenticationFunc(func(_ context.Context, request AuthorizationRequest, _ time.Time) (AuthenticationResult, error) {
				result := interactiveAuthentication(request.Subject.ID, now)
				result.Proof.VerifiedAt = verifiedAt
				result.Proof.ExpiresAt = now.Add(time.Hour)
				return result, nil
			})
			decision := policy.Authorize(AuthorizationRequest{
				Subject: PrincipalRef{ID: "user-tenant-admin"},
				Action:  ActionProjectRead,
				Target:  testTarget("org-a", "tenant-a", "project-a"),
				Context: RequestContext{CorrelationID: "corr-proof-boundary-" + name, Reason: "proof boundary"},
			})
			if !decision.Allowed {
				t.Fatalf("Authorize rejected %s boundary: %#v", name, decision)
			}
		})
	}
}

func interactiveAuthentication(subjectID string, now time.Time) AuthenticationResult {
	return AuthenticationResult{
		SubjectID:       subjectID,
		CredentialClass: CredentialClassInteractiveSession,
		MFA:             MFAAssurance{Required: true, Satisfied: true, MethodClass: MFAMethodExternalIDP},
		Session:         SessionAssurance{State: SessionStateFresh, MaxAgeSeconds: 3600},
		Proof:           AuthenticationProof{VerifiedAt: now, ExpiresAt: now.Add(time.Hour)},
	}
}
