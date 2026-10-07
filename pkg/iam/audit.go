// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type AuditEvent struct {
	Actor              string
	RepresentedSubject string
	Action             Action
	Target             TargetRef
	Reason             string
	TicketRef          string
	CorrelationID      string
	Result             AuditResult
	PolicyRule         string
	Timestamp          time.Time
	Error              string
	BreakGlass         bool
	SupportGrantRef    string
	APITokenRef        string
	TargetPrincipal    string
	TargetLifecycle    TenantState
	TargetNamespace    string
	TargetResource     string
	TargetResourceName string
	TargetOrganization string
	TargetTenant       string
	TargetProject      string
	CredentialClass    CredentialClass
	MFA                MFAAssurance
	Session            SessionAssurance
	Proof              AuthenticationProof
}

type AuditSink interface {
	Append(AuditEvent) error
}

type AuditEventReader interface {
	Events() []AuditEvent
}

type AuditReadiness interface {
	Ready(context.Context) error
}

// DurableAuditSink promises that a successful Append is durably committed and
// that Ready checks the usable persistence dependency. Durable returning false
// is accepted only when PolicyConfig.AllowEphemeralAudit is explicitly set for
// a synthetic or test-only policy.
type DurableAuditSink interface {
	AuditSink
	AuditReadiness
	Durable() bool
}

type SecurityEvent struct {
	Type          string
	Actor         string
	Subject       string
	Result        AuditResult
	Reason        string
	CorrelationID string
	Timestamp     time.Time
}

// SecurityAuditSink lets authentication, login, logout, registration, and
// bootstrap boundaries use the same durable dependency as authorization.
type SecurityAuditSink interface {
	AuditReadiness
	Durable() bool
	AppendSecurityEvent(context.Context, SecurityEvent) error
}

func AppendDurableSecurityEvent(ctx context.Context, sink SecurityAuditSink, event SecurityEvent) error {
	if ctx == nil || sink == nil || !sink.Durable() {
		return ErrAuditRequired
	}
	if strings.TrimSpace(event.Type) == "" || len(event.Type) > 128 ||
		strings.TrimSpace(event.CorrelationID) == "" || len(event.CorrelationID) > 256 ||
		event.Timestamp.IsZero() ||
		(event.Result != AuditResultAllow && event.Result != AuditResultDeny) {
		return fmt.Errorf("security audit event is invalid: %w", ErrAuditRequired)
	}
	if err := sink.Ready(ctx); err != nil {
		return fmt.Errorf("security audit dependency is unavailable: %w", ErrAuditRequired)
	}
	if err := sink.AppendSecurityEvent(ctx, event); err != nil {
		return fmt.Errorf("append security audit event: %w", ErrAuditRequired)
	}
	return nil
}

type MemoryAuditSink struct {
	mu             sync.RWMutex
	events         []AuditEvent
	securityEvents []SecurityEvent
	maxEvents      int
}

func NewMemoryAuditSink() *MemoryAuditSink {
	return NewBoundedMemoryAuditSink(1024)
}

func NewBoundedMemoryAuditSink(maxEvents int) *MemoryAuditSink {
	if maxEvents <= 0 || maxEvents > 4096 {
		maxEvents = 1024
	}
	return &MemoryAuditSink{events: []AuditEvent{}, securityEvents: []SecurityEvent{}, maxEvents: maxEvents}
}

func (sink *MemoryAuditSink) Append(event AuditEvent) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events)+len(sink.securityEvents) >= sink.maxEvents {
		return errors.New("iam: ephemeral audit capacity reached")
	}
	sink.events = append(sink.events, event)
	return nil
}

func (sink *MemoryAuditSink) Events() []AuditEvent {
	sink.mu.RLock()
	defer sink.mu.RUnlock()
	return append([]AuditEvent{}, sink.events...)
}

func (sink *MemoryAuditSink) SecurityEvents() []SecurityEvent {
	sink.mu.RLock()
	defer sink.mu.RUnlock()
	return append([]SecurityEvent{}, sink.securityEvents...)
}

func (sink *MemoryAuditSink) AppendSecurityEvent(_ context.Context, event SecurityEvent) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events)+len(sink.securityEvents) >= sink.maxEvents {
		return errors.New("iam: ephemeral audit capacity reached")
	}
	sink.securityEvents = append(sink.securityEvents, event)
	return nil
}

func (*MemoryAuditSink) Ready(context.Context) error {
	return nil
}

func (*MemoryAuditSink) Durable() bool {
	return false
}

type FailingAuditSink struct{}

func (FailingAuditSink) Append(AuditEvent) error {
	return ErrAuditRequired
}

func (FailingAuditSink) Events() []AuditEvent {
	return nil
}

func (FailingAuditSink) Ready(context.Context) error {
	return nil
}

func (FailingAuditSink) Durable() bool {
	return true
}
