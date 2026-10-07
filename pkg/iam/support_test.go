// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package iam

import (
	"errors"
	"testing"
	"time"
)

func TestSupportAccessRequiresTicketReferenceScopeExpiryReasonAndAudit(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	request := AuthorizationRequest{
		Subject:         PrincipalRef{ID: "support-user"},
		Action:          ActionProjectRead,
		Target:          testTarget("org-a", "tenant-a", "project-a"),
		SupportGrantRef: "support-grant-a",
		Context: RequestContext{
			CorrelationID: "corr-support",
			TicketRef:     "SUP-1234",
			Reason:        "tenant requested diagnostics",
			Now:           now,
		},
	}

	// When
	decision := policy.Authorize(request)

	// Then
	if !decision.Allowed {
		t.Fatalf("Authorize denied support grant: %#v", decision)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultAllow, ActionProjectRead, "support_grant")
}

func TestSupportAccessWithoutTicketReferenceDeniedAndAudited(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	request := AuthorizationRequest{
		Subject:         PrincipalRef{ID: "support-user"},
		Action:          ActionProjectRead,
		Target:          testTarget("org-a", "tenant-a", "project-a"),
		SupportGrantRef: "support-grant-a",
		Context: RequestContext{
			CorrelationID: "corr-support-no-ticket",
			Reason:        "tenant requested diagnostics",
			Now:           now,
		},
	}

	// When
	decision := policy.Authorize(request)

	// Then
	if decision.Allowed {
		t.Fatalf("Authorize allowed support access without ticket: %#v", decision)
	}
	if !errors.Is(decision.Err, ErrTicketRequired) {
		t.Fatalf("Authorize error = %v, want ErrTicketRequired", decision.Err)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionProjectRead, "support_ticket_required")
}
