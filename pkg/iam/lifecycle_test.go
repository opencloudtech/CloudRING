// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package iam

import (
	"errors"
	"testing"
	"time"
)

func TestTenantLifecycleSuspendedTenantWriteDenied(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	policy.Tenants["tenant-a"] = Tenant{
		ID:    "tenant-a",
		OrgID: "org-a",
		State: TenantStateSuspended,
		Quotas: Quotas{
			Projects: 5,
			CPU:      16,
			MemoryGB: 64,
		},
	}
	request := AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin"},
		Action:  ActionProjectWrite,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{CorrelationID: "corr-suspended", Reason: "write while suspended", Now: now},
	}

	// When
	decision := policy.Authorize(request)

	// Then
	if decision.Allowed {
		t.Fatalf("Authorize allowed suspended tenant write: %#v", decision)
	}
	if !errors.Is(decision.Err, ErrTenantSuspended) {
		t.Fatalf("Authorize error = %v, want ErrTenantSuspended", decision.Err)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionProjectWrite, "tenant_lifecycle_write_denied")
}

func TestTenantLifecycleUnknownStateFailsClosed(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	for _, state := range []TenantState{"", "unexpected"} {
		t.Run(string(state), func(t *testing.T) {
			policy := testPolicy(now)
			tenant := policy.Tenants["tenant-a"]
			tenant.State = state
			policy.Tenants["tenant-a"] = tenant

			decision := policy.Authorize(AuthorizationRequest{
				Subject: PrincipalRef{ID: "user-tenant-admin"},
				Action:  ActionProjectRead,
				Target:  testTarget("org-a", "tenant-a", "project-a"),
				Context: RequestContext{CorrelationID: "corr-invalid-lifecycle"},
			})
			if decision.Allowed || !errors.Is(decision.Err, ErrTenantState) {
				t.Fatalf("Authorize accepted invalid lifecycle %q: %#v", state, decision)
			}
		})
	}
}

func TestTenantLifecycleAllowsAuditedExportAction(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	policy.Tenants["tenant-a"] = Tenant{ID: "tenant-a", OrgID: "org-a", State: TenantStateSuspended}

	for _, action := range []Action{ActionTenantExport} {
		t.Run(string(action), func(t *testing.T) {
			request := AuthorizationRequest{
				Subject: PrincipalRef{ID: "platform-admin"},
				Action:  action,
				Target:  testTarget("org-a", "tenant-a", "project-a"),
				Context: RequestContext{CorrelationID: "corr-" + string(action), Reason: "operator lifecycle action", Now: now},
			}

			// When
			decision := policy.Authorize(request)

			// Then
			if !decision.Allowed {
				t.Fatalf("Authorize denied lifecycle action %s: %#v", action, decision)
			}
			requireAudit(t, policy.AuditEvents(), AuditResultAllow, action, "platform_admin_lifecycle")
		})
	}
}

func TestTenantRecoveryRequiresBreakGlassContext(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	decision := policy.Authorize(AuthorizationRequest{
		Subject: PrincipalRef{ID: "platform-admin"},
		Action:  ActionTenantRecover,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{CorrelationID: "corr-recover-no-break-glass", Reason: "recover without emergency context"},
	})
	if decision.Allowed || !errors.Is(decision.Err, ErrBreakGlass) {
		t.Fatalf("Authorize accepted tenant recovery without break-glass: %#v", decision)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionTenantRecover, "break_glass_required")
}

func TestTenantLastOwnerRemovalDeniedAndAudited(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	request := AuthorizationRequest{
		Subject: PrincipalRef{ID: "owner-a"},
		Action:  ActionOwnerRemove,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{
			CorrelationID:   "corr-last-owner",
			Reason:          "remove owner",
			Now:             now,
			TargetPrincipal: "owner-a",
		},
	}

	// When
	decision := policy.Authorize(request)

	// Then
	if decision.Allowed {
		t.Fatalf("Authorize allowed last owner removal: %#v", decision)
	}
	if !errors.Is(decision.Err, ErrLastOwner) {
		t.Fatalf("Authorize error = %v, want ErrLastOwner", decision.Err)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionOwnerRemove, "last_owner_guard")
}

func TestOwnerRemovalRejectsNonOwnerTarget(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	decision := policy.Authorize(AuthorizationRequest{
		Subject: PrincipalRef{ID: "owner-a"},
		Action:  ActionOwnerRemove,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{
			CorrelationID:   "corr-non-owner-target",
			Reason:          "attempt to remove non-owner",
			TargetPrincipal: "user-tenant-admin",
		},
	})
	if decision.Allowed || !errors.Is(decision.Err, ErrTargetPrincipal) {
		t.Fatalf("Authorize accepted a non-owner removal target: %#v", decision)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionOwnerRemove, "owner_target_denied")
}

func TestOwnerRemovalGuardsApplyToEveryCredentialClass(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	tests := []struct {
		name    string
		request AuthorizationRequest
		prepare func(*Policy)
	}{
		{
			name:    "interactive session",
			request: AuthorizationRequest{Subject: PrincipalRef{ID: "owner-a"}},
		},
		{
			name: "break glass",
			request: AuthorizationRequest{
				Subject:    PrincipalRef{ID: "platform-admin"},
				BreakGlass: true,
			},
		},
		{
			name: "support grant",
			request: AuthorizationRequest{
				Subject:         PrincipalRef{ID: "support-user"},
				SupportGrantRef: "support-owner-remove",
			},
			prepare: func(policy *Policy) {
				policy.SupportGrants["support-owner-remove"] = SupportGrant{
					Reference: "support-owner-remove", SubjectID: "support-user",
					TenantID: "tenant-a", ProjectID: "project-a",
					Actions: []Action{ActionOwnerRemove}, Reason: "approved owner maintenance",
					TicketRef: "SUP-OWNER", ExpiresAt: now.Add(time.Hour),
				}
			},
		},
		{
			name: "short-lived api token",
			request: AuthorizationRequest{
				Subject: PrincipalRef{ID: "owner-a", APITokenRef: "tok-owner-remove"},
			},
			prepare: func(policy *Policy) {
				policy.APITokens["tok-owner-remove"] = APIToken{
					Reference: "tok-owner-remove", SubjectID: "owner-a",
					SecretHashRef: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					TenantID:      "tenant-a", ProjectID: "project-a",
					Scopes: []Action{ActionOwnerRemove}, ExpiresAt: now.Add(time.Hour),
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, guard := range []struct {
				name            string
				targetPrincipal string
				want            error
				rule            string
			}{
				{name: "non-owner target", targetPrincipal: "user-tenant-admin", want: ErrTargetPrincipal, rule: "owner_target_denied"},
				{name: "last owner", targetPrincipal: "owner-a", want: ErrLastOwner, rule: "last_owner_guard"},
			} {
				t.Run(guard.name, func(t *testing.T) {
					policy := testPolicy(now)
					if test.prepare != nil {
						test.prepare(policy)
					}
					request := test.request
					request.Action = ActionOwnerRemove
					request.Target = testTarget("org-a", "tenant-a", "project-a")
					request.Context = RequestContext{
						CorrelationID: "corr-owner-guard-" + test.name + "-" + guard.name,
						Reason:        "guard owner membership", TicketRef: "SUP-OWNER",
						TargetPrincipal: guard.targetPrincipal,
					}

					decision := policy.Authorize(request)
					if decision.Allowed || !errors.Is(decision.Err, guard.want) {
						t.Fatalf("Authorize bypassed %s with %s: %#v", guard.name, test.name, decision)
					}
					requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionOwnerRemove, guard.rule)
				})
			}
		})
	}
}

func TestLastOwnerGuardCountsDistinctPrincipalsNotMembershipRows(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	owner := policy.Principals["owner-a"]
	owner.Memberships = append(owner.Memberships, owner.Memberships[0])
	policy.Principals[owner.ID] = owner

	decision := policy.Authorize(AuthorizationRequest{
		Subject: PrincipalRef{ID: owner.ID},
		Action:  ActionOwnerRemove,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{
			CorrelationID: "corr-duplicate-owner-membership", Reason: "remove duplicated owner membership",
			TargetPrincipal: owner.ID,
		},
	})
	if decision.Allowed || !errors.Is(decision.Err, ErrLastOwner) {
		t.Fatalf("Authorize counted duplicate memberships as distinct owners: %#v", decision)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionOwnerRemove, "last_owner_guard")
}
