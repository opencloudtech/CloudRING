// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package iam

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAPITokenScopedExpiringRevocableAndTenantBound(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	request := AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin", APITokenRef: "tok-project-a"},
		Action:  ActionProjectWrite,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{CorrelationID: "corr-api-token", Reason: "automation write", Now: now},
	}

	// When
	decision := policy.Authorize(request)

	// Then
	if !decision.Allowed {
		t.Fatalf("Authorize denied scoped API credential reference: %#v", decision)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultAllow, ActionProjectWrite, "api_token_scope")
}

func TestAPITokenModelStoresOnlySafeSecretMetadata(t *testing.T) {
	// Given
	tokenType := reflect.TypeOf(APIToken{})
	source, err := os.ReadFile("types.go")
	if err != nil {
		t.Fatalf("read APIToken source: %v", err)
	}

	for i := 0; i < tokenType.NumField(); i++ {
		field := tokenType.Field(i)
		lowerName := strings.ToLower(field.Name)
		if strings.Contains(lowerName, "plaintext") || strings.Contains(lowerName, "raw") {
			t.Fatalf("APIToken exposes unsafe secret material field %q", field.Name)
		}
		if strings.Contains(lowerName, "secret") && !strings.Contains(lowerName, "hash") && !strings.HasSuffix(field.Name, "Ref") {
			t.Fatalf("APIToken secret field %q is not safe metadata", field.Name)
		}
	}
	for _, forbidden := range []string{"PlaintextSecret", "RawSecret", "SecretMaterial"} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("APIToken source contains forbidden token material field %q", forbidden)
		}
	}
}

func TestAPITokenWithoutSecretMetadataDeniedAndAudited(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	policy.APITokens["tok-project-a"] = APIToken{
		Reference: "tok-project-a",
		SubjectID: "user-tenant-admin",
		TenantID:  "tenant-a",
		ProjectID: "project-a",
		Scopes:    []Action{ActionProjectWrite},
		ExpiresAt: now.Add(time.Hour),
	}
	request := AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin", APITokenRef: "tok-project-a"},
		Action:  ActionProjectWrite,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{CorrelationID: "corr-token-no-secret-metadata", Reason: "automation write", Now: now},
	}

	// When
	decision := policy.Authorize(request)

	// Then
	if decision.Allowed {
		t.Fatalf("Authorize allowed API token without safe secret metadata: %#v", decision)
	}
	if !errors.Is(decision.Err, ErrTokenScope) {
		t.Fatalf("Authorize error = %v, want ErrTokenScope", decision.Err)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionProjectWrite, "api_token_denied")
}

func TestAPITokenExpiredRevokedOrSuspendedDenied(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	cases := []struct {
		name    string
		mutate  func(*Policy)
		wantErr error
		rule    string
	}{
		{
			name: "expired token",
			mutate: func(policy *Policy) {
				apiGrant := policy.APITokens["tok-project-a"]
				apiGrant.ExpiresAt = now.Add(-time.Second)
				policy.APITokens["tok-project-a"] = apiGrant
			},
			wantErr: ErrTokenExpired,
			rule:    "api_token_denied",
		},
		{
			name: "revoked token",
			mutate: func(policy *Policy) {
				apiGrant := policy.APITokens["tok-project-a"]
				apiGrant.RevokedAt = now.Add(-time.Minute)
				policy.APITokens["tok-project-a"] = apiGrant
			},
			wantErr: ErrTokenRevoked,
			rule:    "api_token_denied",
		},
		{
			name: "suspended tenant",
			mutate: func(policy *Policy) {
				policy.Tenants["tenant-a"] = Tenant{ID: "tenant-a", OrgID: "org-a", State: TenantStateSuspended}
			},
			wantErr: ErrTenantSuspended,
			rule:    "tenant_lifecycle_write_denied",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := testPolicy(now)
			tc.mutate(policy)
			request := AuthorizationRequest{
				Subject: PrincipalRef{ID: "user-tenant-admin", APITokenRef: "tok-project-a"},
				Action:  ActionProjectWrite,
				Target:  testTarget("org-a", "tenant-a", "project-a"),
				Context: RequestContext{CorrelationID: "corr-token-negative", Reason: "automation write", Now: now},
			}

			// When
			decision := policy.Authorize(request)

			// Then
			if decision.Allowed {
				t.Fatalf("Authorize allowed %s: %#v", tc.name, decision)
			}
			if !errors.Is(decision.Err, tc.wantErr) {
				t.Fatalf("Authorize error = %v, want %v", decision.Err, tc.wantErr)
			}
			requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionProjectWrite, tc.rule)
		})
	}
}

func TestCallerTimestampCannotReviveExpiredAPIToken(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	apiGrant := policy.APITokens["tok-project-a"]
	apiGrant.ExpiresAt = now.Add(-time.Second)
	policy.APITokens["tok-project-a"] = apiGrant

	decision := policy.Authorize(AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin", APITokenRef: "tok-project-a"},
		Action:  ActionProjectRead,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{
			CorrelationID: "corr-untrusted-time",
			Reason:        "attempt replay with caller time",
			Now:           now.Add(-24 * time.Hour),
		},
	})

	if decision.Allowed || !errors.Is(decision.Err, ErrTokenExpired) {
		t.Fatalf("Authorize used caller-controlled time: %#v", decision)
	}
}
