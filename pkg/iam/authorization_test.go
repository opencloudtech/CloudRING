// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package iam

import (
	"errors"
	"testing"
	"time"
)

func TestTenantAdminCanManageOwnProject(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	request := AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin"},
		Action:  ActionProjectManage,
		Target: TargetRef{
			OrgID:     "org-a",
			TenantID:  "tenant-a",
			ProjectID: "project-a",
			Namespace: "tenant-a-system",
			Resource:  "project",
			Name:      "project-a",
		},
		Context: RequestContext{
			CorrelationID: "corr-own-project",
			Reason:        "tenant admin manages project quota",
			Now:           now,
		},
	}

	// When
	decision := policy.Authorize(request)

	// Then
	if !decision.Allowed {
		t.Fatalf("Authorize denied tenant admin: %#v", decision)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultAllow, ActionProjectManage, "tenant_admin_project_manage")
}

func TestTenantAdminCannotWriteOutsideProjectNamespaceOrScopes(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	request := AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin"},
		Action:  ActionProjectWrite,
		Target: TargetRef{
			OrgID:     "org-a",
			TenantID:  "tenant-a",
			ProjectID: "project-a",
			Namespace: "tenant-b-system",
			Resource:  "secret",
			Name:      "foreign-namespace-secret",
		},
		Context: RequestContext{
			CorrelationID: "corr-namespace-escape",
			Reason:        "attempted write outside project namespace",
			Now:           now,
		},
	}

	// When
	decision := policy.Authorize(request)

	// Then
	if decision.Allowed {
		t.Fatalf("Authorize allowed namespace escape: %#v", decision)
	}
	if !errors.Is(decision.Err, ErrObjectScope) {
		t.Fatalf("Authorize error = %v, want ErrObjectScope", decision.Err)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionProjectWrite, "object_scope_denied")
}

func TestTenantAdminScopeActionMismatchDeniedAndAudited(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	request := AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin"},
		Action:  ActionProjectWrite,
		Target: TargetRef{
			OrgID:     "org-a",
			TenantID:  "tenant-a",
			ProjectID: "project-a",
			Namespace: "tenant-a-readonly",
			Resource:  "configmap",
			Name:      "readonly-scope-config",
		},
		Context: RequestContext{
			CorrelationID: "corr-scope-action-mismatch",
			Reason:        "attempted write to read-only object scope",
			Now:           now,
		},
	}

	// When
	decision := policy.Authorize(request)

	// Then
	if decision.Allowed {
		t.Fatalf("Authorize allowed object scope action mismatch: %#v", decision)
	}
	if !errors.Is(decision.Err, ErrObjectScope) {
		t.Fatalf("Authorize error = %v, want ErrObjectScope", decision.Err)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionProjectWrite, "object_scope_denied")
}

func TestTenantAdminCanReadConfiguredProjectScope(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	request := AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin"},
		Action:  ActionProjectRead,
		Target: TargetRef{
			OrgID:     "org-a",
			TenantID:  "tenant-a",
			ProjectID: "project-a",
			Namespace: "tenant-a-readonly",
			Resource:  "configmap",
			Name:      "readonly-scope-config",
		},
		Context: RequestContext{
			CorrelationID: "corr-scope-read",
			Reason:        "read from configured object scope",
			Now:           now,
		},
	}

	// When
	decision := policy.Authorize(request)

	// Then
	if !decision.Allowed {
		t.Fatalf("Authorize denied configured object scope read: %#v", decision)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultAllow, ActionProjectRead, "tenant_admin")
}

func TestCrossTenantWriteDeniedAndAudited(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	request := AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin"},
		Action:  ActionProjectWrite,
		Target: TargetRef{
			OrgID:     "org-b",
			TenantID:  "tenant-b",
			ProjectID: "project-b",
			Namespace: "tenant-b-system",
			Resource:  "subscription",
			Name:      "sub-b",
		},
		Context: RequestContext{
			CorrelationID: "corr-cross-tenant",
			Reason:        "attempted cross tenant write",
			Now:           now,
		},
	}

	// When
	decision := policy.Authorize(request)

	// Then
	if decision.Allowed {
		t.Fatalf("Authorize allowed cross-tenant write: %#v", decision)
	}
	if !errors.Is(decision.Err, ErrCrossTenant) {
		t.Fatalf("Authorize error = %v, want ErrCrossTenant", decision.Err)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionProjectWrite, "cross_tenant_denied")
	event := policy.AuditEvents()[len(policy.AuditEvents())-1]
	t.Logf("deny_plus_audit allowed=%t result=%s rule=%s actor=%s action=%s tenant=%s project=%s correlation=%s error=%s",
		decision.Allowed,
		event.Result,
		event.PolicyRule,
		event.Actor,
		event.Action,
		event.Target.TenantID,
		event.Target.ProjectID,
		event.CorrelationID,
		event.Error,
	)
}

func TestIAMDeniesUnknownInputsFailClosedAndAudited(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	cases := []struct {
		name    string
		request AuthorizationRequest
		wantErr error
	}{
		{
			name: "unknown user",
			request: AuthorizationRequest{
				Subject: PrincipalRef{ID: "missing-user"},
				Action:  ActionProjectRead,
				Target:  testTarget("org-a", "tenant-a", "project-a"),
				Context: RequestContext{CorrelationID: "corr-missing-user", Reason: "read", Now: now},
			},
			wantErr: ErrUnknownPrincipal,
		},
		{
			name: "unknown action",
			request: AuthorizationRequest{
				Subject: PrincipalRef{ID: "user-tenant-admin"},
				Action:  Action("project.teleport"),
				Target:  testTarget("org-a", "tenant-a", "project-a"),
				Context: RequestContext{CorrelationID: "corr-unknown-action", Reason: "read", Now: now},
			},
			wantErr: ErrUnknownAction,
		},
		{
			name: "unknown project",
			request: AuthorizationRequest{
				Subject: PrincipalRef{ID: "user-tenant-admin"},
				Action:  ActionProjectRead,
				Target:  testTarget("org-a", "tenant-a", "missing-project"),
				Context: RequestContext{CorrelationID: "corr-missing-project", Reason: "read", Now: now},
			},
			wantErr: ErrUnknownProject,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// When
			decision := policy.Authorize(tc.request)

			// Then
			if decision.Allowed {
				t.Fatalf("Authorize allowed %s: %#v", tc.name, decision)
			}
			if !errors.Is(decision.Err, tc.wantErr) {
				t.Fatalf("Authorize error = %v, want %v", decision.Err, tc.wantErr)
			}
			requireAudit(t, policy.AuditEvents(), AuditResultDeny, tc.request.Action, "fail_closed")
		})
	}
}
