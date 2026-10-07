// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package iam

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUnknownPrincipal = errors.New("iam: unknown principal")
	ErrUnknownAction    = errors.New("iam: unknown action")
	ErrUnknownTenant    = errors.New("iam: unknown tenant")
	ErrUnknownProject   = errors.New("iam: unknown project")
	ErrCrossTenant      = errors.New("iam: cross-tenant access denied")
	ErrObjectScope      = errors.New("iam: object scope denied")
	ErrTenantSuspended  = errors.New("iam: tenant suspended")
	ErrTenantDeleting   = errors.New("iam: tenant deleting")
	ErrTenantState      = errors.New("iam: invalid tenant lifecycle state")
	ErrLastOwner        = errors.New("iam: last owner removal denied")
	ErrReasonRequired   = errors.New("iam: explicit reason required")
	ErrTicketRequired   = errors.New("iam: support ticket reference required")
	ErrAuditRequired    = errors.New("iam: durable audit required")
	ErrTokenExpired     = errors.New("iam: api token expired")
	ErrTokenRevoked     = errors.New("iam: api token revoked")
	ErrTokenScope       = errors.New("iam: api token scope denied")
	ErrSupportGrant     = errors.New("iam: support grant denied")
	ErrRoleDenied       = errors.New("iam: role denied")
	ErrAuthentication   = errors.New("iam: trusted authentication evidence required")
	ErrMFARequired      = errors.New("iam: multi-factor assurance required")
	ErrSessionAssurance = errors.New("iam: fresh session assurance required")
	ErrBreakGlass       = errors.New("iam: break-glass context required")
	ErrTargetPrincipal  = errors.New("iam: target principal is not an owner of the project")
)

type Action string

const (
	ActionProjectRead   Action = "project.read"
	ActionProjectWrite  Action = "project.write"
	ActionProjectManage Action = "project.manage"
	ActionOwnerRemove   Action = "owner.remove"
	ActionTenantExport  Action = "tenant.export"
	ActionTenantRecover Action = "tenant.recover"
)

type Role string

const (
	RoleOwner         Role = "owner"
	RoleTenantAdmin   Role = "tenant_admin"
	RoleTenantViewer  Role = "tenant_viewer"
	RoleSupport       Role = "support"
	RolePlatformAdmin Role = "platform_admin"
)

type TenantState string

const (
	TenantStateActive     TenantState = "active"
	TenantStateSuspended  TenantState = "suspended"
	TenantStateDeleting   TenantState = "deleting"
	TenantStateRecovering TenantState = "recovering"
	TenantStateExporting  TenantState = "exporting"
)

type AuditResult string

const (
	AuditResultAllow AuditResult = "allow"
	AuditResultDeny  AuditResult = "deny"
)

type CredentialClass string

const (
	CredentialClassInteractiveSession CredentialClass = "interactive_session"
	CredentialClassShortLivedAPIToken CredentialClass = "short_lived_api_token"
	CredentialClassSupportGrant       CredentialClass = "support_grant"
	CredentialClassBreakGlass         CredentialClass = "break_glass"
)

type MFAMethodClass string

const (
	MFAMethodNone        MFAMethodClass = "none"
	MFAMethodTOTP        MFAMethodClass = "totp"
	MFAMethodWebAuthn    MFAMethodClass = "webauthn"
	MFAMethodHardwareKey MFAMethodClass = "hardware_key"
	MFAMethodExternalIDP MFAMethodClass = "external_idp"
)

type MFAAssurance struct {
	Required    bool
	Satisfied   bool
	MethodClass MFAMethodClass
}

type SessionState string

const (
	SessionStateFresh   SessionState = "fresh"
	SessionStateStale   SessionState = "stale"
	SessionStateAbsent  SessionState = "absent"
	SessionStateRevoked SessionState = "revoked"
)

type SessionAssurance struct {
	State SessionState
	// MaxAgeSeconds is the verifier-declared maximum age of Proof.VerifiedAt
	// for this session. Policy also applies its own stricter maximum.
	MaxAgeSeconds            int64
	ReauthenticationRequired bool
}

type AuthenticationProof struct {
	// VerifiedAt is when the trusted verifier completed credential validation.
	// ExpiresAt is the credential or proof expiry, whichever comes first.
	VerifiedAt time.Time
	ExpiresAt  time.Time
}

// AuthenticationResult is returned only by the trusted verifier configured
// on Policy. It is deliberately not part of AuthorizationRequest, so callers
// cannot turn a subject or API-token reference into authentication evidence.
type AuthenticationResult struct {
	SubjectID       string
	APITokenRef     string
	CredentialClass CredentialClass
	MFA             MFAAssurance
	Session         SessionAssurance
	Proof           AuthenticationProof
}

type AuthenticationVerifier interface {
	Authenticate(context.Context, AuthorizationRequest, time.Time) (AuthenticationResult, error)
}

type AuthenticationFunc func(context.Context, AuthorizationRequest, time.Time) (AuthenticationResult, error)

func (verify AuthenticationFunc) Authenticate(ctx context.Context, request AuthorizationRequest, at time.Time) (AuthenticationResult, error) {
	if verify == nil {
		return AuthenticationResult{}, ErrAuthentication
	}
	return verify(ctx, request, at)
}

type Organization struct {
	ID   string
	Name string
}

type Tenant struct {
	ID     string
	OrgID  string
	State  TenantState
	Quotas Quotas
}

type Quotas struct {
	Projects int
	CPU      int
	MemoryGB int
}

type Project struct {
	ID        string
	TenantID  string
	OrgID     string
	Namespace string
	Scopes    []NamespaceScope
}

type NamespaceScope struct {
	Namespace string
	Actions   []Action
}

type Principal struct {
	ID          string
	Groups      []string
	Memberships []Membership
	Support     bool
}

type Membership struct {
	OrgID     string
	TenantID  string
	ProjectID string
	Role      Role
}

type PrincipalRef struct {
	ID          string
	APITokenRef string
}

type TargetRef struct {
	OrgID     string
	TenantID  string
	ProjectID string
	Namespace string
	Resource  string
	Name      string
}

type RequestContext struct {
	TicketRef     string
	CorrelationID string
	Reason        string
	// Now is retained for wire compatibility but is never trusted for policy
	// evaluation. PolicyConfig.Clock is the authoritative time source.
	Now             time.Time
	TargetPrincipal string
}

type AuthorizationRequest struct {
	Subject         PrincipalRef
	Action          Action
	Target          TargetRef
	Context         RequestContext
	SupportGrantRef string
	BreakGlass      bool
}

type Decision struct {
	Allowed         bool
	Err             error
	PolicyRule      string
	CredentialClass CredentialClass
	MFA             MFAAssurance
	Session         SessionAssurance
	Proof           AuthenticationProof
}

type APIToken struct {
	Reference     string
	SubjectID     string
	SecretHashRef string
	TenantID      string
	ProjectID     string
	Scopes        []Action
	ExpiresAt     time.Time
	RevokedAt     time.Time
}

type SupportGrant struct {
	Reference string
	SubjectID string
	TenantID  string
	ProjectID string
	Actions   []Action
	TicketRef string
	Reason    string
	ExpiresAt time.Time
}

type Clock interface {
	// Now may be called concurrently by multiple authorization requests.
	Now() time.Time
}

type FixedClock struct {
	At time.Time
}

func (clock FixedClock) Now() time.Time {
	return clock.At
}

type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now().UTC()
}
