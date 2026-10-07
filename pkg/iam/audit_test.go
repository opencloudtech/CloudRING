// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package iam

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuditBreakGlassRequiresReasonAuditBeforeAllow(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	request := AuthorizationRequest{
		Subject:    PrincipalRef{ID: "platform-admin"},
		Action:     ActionProjectWrite,
		Target:     testTarget("org-a", "tenant-a", "project-a"),
		BreakGlass: true,
		Context: RequestContext{
			CorrelationID: "corr-break-glass",
			Reason:        "restore tenant access during incident",
			TicketRef:     "INC-42",
			Now:           now,
		},
	}

	t.Run("allows after audit append succeeds", func(t *testing.T) {
		policy := testPolicy(now)

		// When
		decision := policy.Authorize(request)

		// Then
		if !decision.Allowed {
			t.Fatalf("Authorize denied audited break-glass: %#v", decision)
		}
		requireAudit(t, policy.AuditEvents(), AuditResultAllow, ActionProjectWrite, "break_glass")
	})

	t.Run("denies when audit append fails", func(t *testing.T) {
		policy := testPolicy(now)
		policy.AuditSink = FailingAuditSink{}

		// When
		decision := policy.Authorize(request)

		// Then
		if decision.Allowed {
			t.Fatalf("Authorize allowed unaudited break-glass: %#v", decision)
		}
		if !errors.Is(decision.Err, ErrAuditRequired) {
			t.Fatalf("Authorize error = %v, want ErrAuditRequired", decision.Err)
		}
	})
}

func TestAuditBreakGlassRequiresTicketReference(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	decision := policy.Authorize(AuthorizationRequest{
		Subject:    PrincipalRef{ID: "platform-admin"},
		Action:     ActionTenantRecover,
		Target:     testTarget("org-a", "tenant-a", "project-a"),
		BreakGlass: true,
		Context: RequestContext{
			CorrelationID: "corr-break-glass-no-ticket",
			Reason:        "restore tenant access during incident",
			Now:           now,
		},
	})

	if decision.Allowed {
		t.Fatalf("Authorize allowed break-glass without a ticket: %#v", decision)
	}
	if !errors.Is(decision.Err, ErrTicketRequired) {
		t.Fatalf("Authorize error = %v, want ErrTicketRequired", decision.Err)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionTenantRecover, "break_glass_ticket_required")
}

func TestAuditBreakGlassRequiresExplicitReason(t *testing.T) {
	// Given
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)
	request := AuthorizationRequest{
		Subject:    PrincipalRef{ID: "platform-admin"},
		Action:     ActionProjectWrite,
		Target:     testTarget("org-a", "tenant-a", "project-a"),
		BreakGlass: true,
		Context:    RequestContext{CorrelationID: "corr-break-glass-no-reason", Now: now},
	}

	// When
	decision := policy.Authorize(request)

	// Then
	if decision.Allowed {
		t.Fatalf("Authorize allowed break-glass without reason: %#v", decision)
	}
	if !errors.Is(decision.Err, ErrReasonRequired) {
		t.Fatalf("Authorize error = %v, want ErrReasonRequired", decision.Err)
	}
	requireAudit(t, policy.AuditEvents(), AuditResultDeny, ActionProjectWrite, "break_glass_reason_required")
}

func TestMemoryAuditSinkSupportsConcurrentAuthorization(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	policy := testPolicy(now)

	const workers = 32
	var wait sync.WaitGroup
	wait.Add(workers)
	for index := 0; index < workers; index++ {
		go func(index int) {
			defer wait.Done()
			decision := policy.Authorize(AuthorizationRequest{
				Subject: PrincipalRef{ID: "user-tenant-admin"},
				Action:  ActionProjectRead,
				Target:  testTarget("org-a", "tenant-a", "project-a"),
				Context: RequestContext{
					CorrelationID: fmt.Sprintf("concurrent-%d", index),
					Now:           now,
				},
			})
			if !decision.Allowed {
				t.Errorf("Authorize(%d) denied: %#v", index, decision)
			}
		}(index)
	}
	wait.Wait()

	if got := len(policy.AuditEvents()); got != workers {
		t.Fatalf("AuditEvents count = %d, want %d", got, workers)
	}
}

func TestAuthorizeSamplesClockOnceForDecisionAndAudit(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	clock := &countingClock{at: now}
	policy := testPolicy(now)
	policy.clock = clock

	decision := policy.Authorize(AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin"},
		Action:  ActionProjectRead,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{CorrelationID: "corr-single-clock", Reason: "single clock sample"},
	})
	if !decision.Allowed {
		t.Fatalf("Authorize denied: %#v", decision)
	}
	if calls := clock.calls.Load(); calls != 1 {
		t.Fatalf("Clock.Now calls = %d, want 1", calls)
	}
	if event := policy.AuditEvents()[0]; !event.Timestamp.Equal(now) {
		t.Fatalf("audit timestamp = %s, want %s", event.Timestamp, now)
	}
}

func TestAuditDependencyMustBeExplicitDurableAndReady(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	request := AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin"},
		Action:  ActionProjectRead,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{CorrelationID: "corr-audit-dependency", Reason: "audit dependency contract"},
	}

	t.Run("nil sink", func(t *testing.T) {
		policy := testPolicy(now)
		policy.AuditSink = nil
		decision := policy.Authorize(request)
		if decision.Allowed || !errors.Is(decision.Err, ErrAuditRequired) {
			t.Fatalf("Authorize accepted nil audit sink: %#v", decision)
		}
	})

	t.Run("ephemeral sink without explicit test allowance", func(t *testing.T) {
		policy := testPolicy(now)
		policy.allowEphemeralAudit = false
		decision := policy.Authorize(request)
		if decision.Allowed || !errors.Is(decision.Err, ErrAuditRequired) {
			t.Fatalf("Authorize accepted implicit ephemeral audit: %#v", decision)
		}
	})

	t.Run("unready durable sink", func(t *testing.T) {
		policy := testPolicy(now)
		policy.AuditSink = unavailableDurableAuditSink{}
		decision := policy.Authorize(request)
		if decision.Allowed || !errors.Is(decision.Err, ErrAuditRequired) {
			t.Fatalf("Authorize accepted unready durable audit: %#v", decision)
		}
	})
}

func TestMemoryAuditSinkIsBounded(t *testing.T) {
	sink := NewBoundedMemoryAuditSink(1)
	if err := sink.Append(AuditEvent{}); err != nil {
		t.Fatalf("first memory audit append failed: %v", err)
	}
	if err := sink.Append(AuditEvent{}); err == nil {
		t.Fatal("bounded memory audit accepted an event beyond capacity")
	}
}

func TestAppendDurableSecurityEventUsesSameFailClosedBoundary(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	event := SecurityEvent{
		Type:          "identity.login",
		Actor:         "verified-subject",
		Subject:       "verified-subject",
		Result:        AuditResultAllow,
		Reason:        "oidc authentication succeeded",
		CorrelationID: "corr-security-audit",
		Timestamp:     now,
	}
	if err := AppendDurableSecurityEvent(context.Background(), NewMemoryAuditSink(), event); !errors.Is(err, ErrAuditRequired) {
		t.Fatalf("ephemeral security audit error = %v, want ErrAuditRequired", err)
	}
	sink := &recordingSecurityAuditSink{}
	if err := AppendDurableSecurityEvent(context.Background(), sink, event); err != nil {
		t.Fatalf("AppendDurableSecurityEvent: %v", err)
	}
	if len(sink.events) != 1 || sink.events[0].CorrelationID != event.CorrelationID {
		t.Fatalf("security event was not durably appended: %#v", sink.events)
	}
	sink.readyErr = errors.New("unavailable")
	if err := AppendDurableSecurityEvent(context.Background(), sink, event); !errors.Is(err, ErrAuditRequired) {
		t.Fatalf("unready security audit error = %v, want ErrAuditRequired", err)
	}
}

type unavailableDurableAuditSink struct{}

func (unavailableDurableAuditSink) Append(AuditEvent) error {
	return nil
}

func (unavailableDurableAuditSink) Ready(context.Context) error {
	return errors.New("unavailable")
}

func (unavailableDurableAuditSink) Durable() bool {
	return true
}

type recordingSecurityAuditSink struct {
	events   []SecurityEvent
	readyErr error
}

func (sink *recordingSecurityAuditSink) AppendSecurityEvent(_ context.Context, event SecurityEvent) error {
	sink.events = append(sink.events, event)
	return nil
}

func (sink *recordingSecurityAuditSink) Ready(context.Context) error {
	return sink.readyErr
}

func (*recordingSecurityAuditSink) Durable() bool {
	return true
}

type countingClock struct {
	at    time.Time
	calls atomic.Int64
}

func (clock *countingClock) Now() time.Time {
	clock.calls.Add(1)
	return clock.at
}
