// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package iam

import (
	"context"
	"fmt"
	"time"
)

func (policy *Policy) audit(ctx context.Context, request AuthorizationRequest, subject resolvedSubject, decision Decision, now time.Time) Decision {
	result := AuditResultDeny
	if decision.Allowed {
		result = AuditResultAllow
	}
	event := AuditEvent{
		Actor:              subject.actor,
		RepresentedSubject: subject.represented,
		Action:             request.Action,
		Target:             request.Target,
		Reason:             request.Context.Reason,
		TicketRef:          request.Context.TicketRef,
		CorrelationID:      request.Context.CorrelationID,
		Result:             result,
		PolicyRule:         decision.PolicyRule,
		Timestamp:          now,
		BreakGlass:         request.BreakGlass,
		SupportGrantRef:    request.SupportGrantRef,
		APITokenRef:        request.Subject.APITokenRef,
		TargetPrincipal:    request.Context.TargetPrincipal,
		TargetNamespace:    request.Target.Namespace,
		TargetResource:     request.Target.Resource,
		TargetResourceName: request.Target.Name,
		TargetOrganization: request.Target.OrgID,
		TargetTenant:       request.Target.TenantID,
		TargetProject:      request.Target.ProjectID,
		CredentialClass:    decision.CredentialClass,
		MFA:                decision.MFA,
		Session:            decision.Session,
		Proof:              decision.Proof,
	}
	if decision.Err != nil {
		event.Error = decision.Err.Error()
	}
	if tenant, ok := policy.Tenants[request.Target.TenantID]; ok {
		event.TargetLifecycle = tenant.State
	}
	if event.Actor == "" {
		event.Actor = request.Subject.ID
	}
	durableSink, ok := policy.AuditSink.(DurableAuditSink)
	if !ok || (!policy.allowEphemeralAudit && !durableSink.Durable()) {
		return auditDenied(decision, ErrAuditRequired)
	}
	if err := durableSink.Ready(ctx); err != nil {
		return auditDenied(decision, ErrAuditRequired)
	}
	if err := policy.AuditSink.Append(event); err != nil {
		return auditDenied(decision, fmt.Errorf("append audit event: %w", ErrAuditRequired))
	}
	return decision
}

func auditDenied(decision Decision, err error) Decision {
	decision.Allowed = false
	decision.Err = err
	decision.PolicyRule = "audit_required"
	return decision
}
