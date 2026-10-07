// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package iam

import (
	"testing"
	"time"
)

func testPolicy(now time.Time) *Policy {
	policy := NewPolicy(PolicyConfig{
		Clock:                         FixedClock{At: now},
		AuditSink:                     NewMemoryAuditSink(),
		AuthenticationVerifier:        syntheticContractAuthenticationVerifier(),
		AuthenticationProofMaxAge:     time.Hour,
		AuthenticationProofFutureSkew: time.Minute,
		AllowEphemeralAudit:           true,
	})
	policy.Organizations["org-a"] = Organization{ID: "org-a", Name: "Org A"}
	policy.Organizations["org-b"] = Organization{ID: "org-b", Name: "Org B"}
	policy.Tenants["tenant-a"] = Tenant{
		ID:    "tenant-a",
		OrgID: "org-a",
		State: TenantStateActive,
		Quotas: Quotas{
			Projects: 5,
			CPU:      16,
			MemoryGB: 64,
		},
	}
	policy.Tenants["tenant-b"] = Tenant{ID: "tenant-b", OrgID: "org-b", State: TenantStateActive}
	policy.Projects["project-a"] = Project{
		ID:        "project-a",
		TenantID:  "tenant-a",
		OrgID:     "org-a",
		Namespace: "tenant-a-system",
		Scopes: []NamespaceScope{
			{Namespace: "tenant-a-readonly", Actions: []Action{ActionProjectRead}},
		},
	}
	policy.Projects["project-b"] = Project{ID: "project-b", TenantID: "tenant-b", OrgID: "org-b", Namespace: "tenant-b-system"}
	policy.Principals["user-tenant-admin"] = Principal{
		ID: "user-tenant-admin",
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
	policy.Principals["platform-admin"] = Principal{
		ID: "platform-admin",
		Memberships: []Membership{
			{OrgID: "org-a", TenantID: "tenant-a", Role: RolePlatformAdmin},
		},
	}
	policy.Principals["support-user"] = Principal{ID: "support-user", Support: true}
	policy.APITokens["tok-project-a"] = APIToken{
		Reference:     "tok-project-a",
		SubjectID:     "user-tenant-admin",
		SecretHashRef: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TenantID:      "tenant-a",
		ProjectID:     "project-a",
		Scopes:        []Action{ActionProjectWrite},
		ExpiresAt:     now.Add(time.Hour),
	}
	policy.SupportGrants["support-grant-a"] = SupportGrant{
		Reference: "support-grant-a",
		SubjectID: "support-user",
		TenantID:  "tenant-a",
		ProjectID: "project-a",
		Actions:   []Action{ActionProjectRead},
		Reason:    "tenant requested diagnostics",
		TicketRef: "SUP-1234",
		ExpiresAt: now.Add(time.Hour),
	}
	return policy
}

func testTarget(orgID, tenantID, projectID string) TargetRef {
	return TargetRef{
		OrgID:     orgID,
		TenantID:  tenantID,
		ProjectID: projectID,
		Namespace: tenantID + "-system",
		Resource:  "project",
		Name:      projectID,
	}
}

func requireAudit(t *testing.T, events []AuditEvent, result AuditResult, action Action, rule string) {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("expected at least one audit event")
	}
	event := events[len(events)-1]
	if event.Result != result {
		t.Fatalf("audit result = %q, want %q in %#v", event.Result, result, event)
	}
	if event.Action != action {
		t.Fatalf("audit action = %q, want %q in %#v", event.Action, action, event)
	}
	if event.PolicyRule != rule {
		t.Fatalf("audit rule = %q, want %q in %#v", event.PolicyRule, rule, event)
	}
	if event.Actor == "" {
		t.Fatalf("audit actor is empty: %#v", event)
	}
	if event.Target.Resource == "" || event.Target.TenantID == "" {
		t.Fatalf("audit target is incomplete: %#v", event)
	}
	if event.CorrelationID == "" {
		t.Fatalf("audit context is incomplete: %#v", event)
	}
	if event.Reason == "" && event.PolicyRule != "break_glass_reason_required" {
		t.Fatalf("audit reason is incomplete: %#v", event)
	}
	if event.Timestamp.IsZero() {
		t.Fatalf("audit timestamp is zero: %#v", event)
	}
}
