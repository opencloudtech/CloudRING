// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package iam

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewPolicyFromStateLoadsRealRoleAndScopeDirectory(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	fixture := testPolicy(now)
	loader := staticPolicyStateLoader{state: PolicyState{
		Organizations: fixture.Organizations,
		Tenants:       fixture.Tenants,
		Projects:      fixture.Projects,
		Principals:    fixture.Principals,
		APITokens:     fixture.APITokens,
		SupportGrants: fixture.SupportGrants,
	}}
	config := PolicyConfig{
		Clock:                         FixedClock{At: now},
		AuditSink:                     &durableMemoryAuditSink{MemoryAuditSink: NewMemoryAuditSink()},
		AuthenticationVerifier:        syntheticContractAuthenticationVerifier(),
		AuthenticationProofMaxAge:     time.Hour,
		AuthenticationProofFutureSkew: time.Minute,
	}
	policy, err := NewPolicyFromState(context.Background(), config, loader)
	if err != nil {
		t.Fatalf("NewPolicyFromState: %v", err)
	}
	decision := policy.Authorize(AuthorizationRequest{
		Subject: PrincipalRef{ID: "user-tenant-admin"},
		Action:  ActionProjectWrite,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{CorrelationID: "state-loader-role-scope", Reason: "loaded role and scope"},
	})
	if !decision.Allowed {
		t.Fatalf("loaded role/scope directory denied valid request: %#v", decision)
	}

	loader.state.Principals["user-tenant-admin"] = Principal{ID: "different-subject"}
	if _, err := NewPolicyFromState(context.Background(), config, loader); err == nil {
		t.Fatal("NewPolicyFromState accepted a mismatched principal reference")
	}
}

func TestNewPolicyFromStateRequiresReadyDurableDependencies(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	fixture := testPolicy(now)
	state := PolicyState{
		Organizations: fixture.Organizations,
		Tenants:       fixture.Tenants,
		Projects:      fixture.Projects,
		Principals:    fixture.Principals,
		APITokens:     fixture.APITokens,
		SupportGrants: fixture.SupportGrants,
	}
	config := PolicyConfig{
		Clock:                         FixedClock{At: now},
		AuditSink:                     &durableMemoryAuditSink{MemoryAuditSink: NewMemoryAuditSink()},
		AuthenticationVerifier:        syntheticContractAuthenticationVerifier(),
		AuthenticationProofMaxAge:     time.Hour,
		AuthenticationProofFutureSkew: time.Minute,
	}
	if _, err := NewPolicyFromState(context.Background(), config, staticPolicyStateLoader{
		state: state, readyErr: errors.New("unavailable"),
	}); err == nil {
		t.Fatal("NewPolicyFromState accepted an unready policy state loader")
	}
	config.AuditSink = NewMemoryAuditSink()
	if _, err := NewPolicyFromState(context.Background(), config, staticPolicyStateLoader{state: state}); !errors.Is(err, ErrAuditRequired) {
		t.Fatalf("NewPolicyFromState ephemeral audit error = %v, want ErrAuditRequired", err)
	}
}

type staticPolicyStateLoader struct {
	state    PolicyState
	readyErr error
	loadErr  error
}

func (loader staticPolicyStateLoader) Ready(context.Context) error {
	return loader.readyErr
}

func (loader staticPolicyStateLoader) LoadPolicyState(context.Context) (PolicyState, error) {
	return loader.state, loader.loadErr
}

type durableMemoryAuditSink struct {
	*MemoryAuditSink
}

func (*durableMemoryAuditSink) Durable() bool {
	return true
}
