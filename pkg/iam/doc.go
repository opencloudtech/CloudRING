// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Package iam implements provider-neutral, fail-closed authorization decisions
// for CloudRING organizations, tenants, projects, support grants, API-token
// references, break-glass controls, and audit sinks.
//
// A subject or API-token reference never authenticates itself. Policy denies
// unless its configured AuthenticationVerifier returns matching trusted
// authentication, MFA, session, credential-class, and bounded proof-freshness
// evidence. OIDCAuthenticationVerifier is the reference adapter that takes the
// subject from a signed OIDC token rather than from the authorization request.
//
// A Policy is configured by populating its exported maps before it starts
// serving requests. Once serving begins, callers must treat that configuration
// as immutable. Authorize and AuditEvents may then be called concurrently when
// the configured Clock, AuthenticationVerifier, and AuditSink are themselves
// safe for concurrent use. MemoryAuditSink is bounded, non-durable, and must be
// explicitly allowed for synthetic or test-only policy. Production decisions
// require a ready DurableAuditSink. Authorize samples its clock once and uses
// that instant for authentication, evaluation, and audit.
package iam
