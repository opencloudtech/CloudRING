// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package iam

import (
	"context"
	"strings"
	"time"
)

type PolicyConfig struct {
	Clock                         Clock
	AuditSink                     AuditSink
	AuthenticationVerifier        AuthenticationVerifier
	AuthenticationProofMaxAge     time.Duration
	AuthenticationProofFutureSkew time.Duration
	AllowEphemeralAudit           bool
}

type Policy struct {
	Organizations       map[string]Organization
	Tenants             map[string]Tenant
	Projects            map[string]Project
	Principals          map[string]Principal
	APITokens           map[string]APIToken
	SupportGrants       map[string]SupportGrant
	clock               Clock
	AuditSink           AuditSink
	authenticator       AuthenticationVerifier
	proofMaxAge         time.Duration
	proofSkew           time.Duration
	allowEphemeralAudit bool
}

type resolvedSubject struct {
	principal   Principal
	actor       string
	represented string
	apiGrant    APIToken
	authnClass  CredentialClass
	mfa         MFAAssurance
	session     SessionAssurance
	proof       AuthenticationProof
}

func NewPolicy(config PolicyConfig) *Policy {
	clock := config.Clock
	if clock == nil {
		clock = systemClock{}
	}
	return &Policy{
		Organizations:       map[string]Organization{},
		Tenants:             map[string]Tenant{},
		Projects:            map[string]Project{},
		Principals:          map[string]Principal{},
		APITokens:           map[string]APIToken{},
		SupportGrants:       map[string]SupportGrant{},
		clock:               clock,
		AuditSink:           config.AuditSink,
		authenticator:       config.AuthenticationVerifier,
		proofMaxAge:         config.AuthenticationProofMaxAge,
		proofSkew:           config.AuthenticationProofFutureSkew,
		allowEphemeralAudit: config.AllowEphemeralAudit,
	}
}

func (policy *Policy) AuditEvents() []AuditEvent {
	reader, ok := policy.AuditSink.(AuditEventReader)
	if !ok {
		return nil
	}
	return reader.Events()
}

func (policy *Policy) Authorize(request AuthorizationRequest) Decision {
	return policy.AuthorizeContext(context.Background(), request)
}

// AuthorizeContext lets a trusted AuthenticationVerifier consume
// transport-specific proof from ctx without placing bearer material in the
// authorization request or audit record.
func (policy *Policy) AuthorizeContext(ctx context.Context, request AuthorizationRequest) Decision {
	if ctx == nil {
		ctx = context.Background()
	}
	now := policy.requestTime()
	authentication, authenticationErr := policy.authenticate(ctx, request, now)
	subject, decision := policy.resolveSubject(request, authentication, authenticationErr, now)
	subject.mfa = normalizedMFA(request, subject.authnClass, subject.mfa)
	if principalRequiresMFA(subject.principal) {
		subject.mfa.Required = true
	}
	if decision.Err == nil {
		decision = policy.evaluate(request, subject, now)
	}
	decision.CredentialClass = subject.authnClass
	decision.MFA = subject.mfa
	decision.Session = subject.session
	decision.Proof = subject.proof
	return policy.audit(ctx, request, subject, decision, now)
}

func (policy *Policy) authenticate(ctx context.Context, request AuthorizationRequest, now time.Time) (AuthenticationResult, error) {
	if ctx == nil || policy.authenticator == nil {
		return AuthenticationResult{}, ErrAuthentication
	}
	result, err := policy.authenticator.Authenticate(ctx, request, now)
	if err != nil {
		return AuthenticationResult{}, ErrAuthentication
	}
	if err := policy.validateAuthenticationProof(result, now); err != nil {
		return AuthenticationResult{}, ErrAuthentication
	}
	return result, nil
}

func (policy *Policy) validateAuthenticationProof(result AuthenticationResult, now time.Time) error {
	const (
		maxConfiguredProofAge  = 24 * time.Hour
		maxConfiguredProofSkew = 5 * time.Minute
	)
	if policy.proofMaxAge <= 0 || policy.proofMaxAge > maxConfiguredProofAge ||
		policy.proofSkew < 0 || policy.proofSkew > maxConfiguredProofSkew {
		return ErrAuthentication
	}
	proof := result.Proof
	if proof.VerifiedAt.IsZero() || proof.ExpiresAt.IsZero() ||
		!proof.ExpiresAt.After(proof.VerifiedAt) || !now.Before(proof.ExpiresAt) ||
		proof.VerifiedAt.After(now.Add(policy.proofSkew)) {
		return ErrAuthentication
	}
	age := now.Sub(proof.VerifiedAt)
	if age < 0 {
		age = 0
	}
	if age > policy.proofMaxAge {
		return ErrAuthentication
	}
	if result.CredentialClass != CredentialClassShortLivedAPIToken {
		maxSessionSeconds := int64(policy.proofMaxAge / time.Second)
		if result.Session.MaxAgeSeconds <= 0 || result.Session.MaxAgeSeconds > maxSessionSeconds ||
			age > time.Duration(result.Session.MaxAgeSeconds)*time.Second {
			return ErrAuthentication
		}
	}
	return nil
}

func (policy *Policy) evaluate(request AuthorizationRequest, subject resolvedSubject, now time.Time) Decision {
	if !knownAction(request.Action) {
		return deny(ErrUnknownAction, "fail_closed")
	}
	if decision := evaluateAssurance(request, subject); decision.Err != nil {
		return decision
	}
	if request.Action == ActionTenantRecover && !request.BreakGlass {
		return deny(ErrBreakGlass, "break_glass_required")
	}
	tenant, project, err := policy.resolveTarget(request.Target)
	if err != nil {
		return deny(err, "fail_closed")
	}
	if !targetWithinProjectScope(request.Target, project, request.Action) {
		return deny(ErrObjectScope, "object_scope_denied")
	}
	if err := lifecycleAllows(tenant.State, request.Action); err != nil {
		return deny(err, "tenant_lifecycle_write_denied")
	}
	// Owner-removal invariants are structural safety checks, not permissions.
	// They must run before every credential-specific allow path.
	if request.Action == ActionOwnerRemove {
		targetPrincipal, ok := policy.Principals[request.Context.TargetPrincipal]
		if !ok || targetPrincipal.ID != request.Context.TargetPrincipal || !principalOwns(targetPrincipal, project) {
			return deny(ErrTargetPrincipal, "owner_target_denied")
		}
		if policy.removingLastOwner(request.Context.TargetPrincipal, project) {
			return deny(ErrLastOwner, "last_owner_guard")
		}
	}
	if request.BreakGlass {
		return policy.evaluateBreakGlass(request, subject)
	}
	if request.SupportGrantRef != "" {
		return policy.evaluateSupportGrant(request, subject, now)
	}
	if request.Subject.APITokenRef != "" {
		if err := policy.evaluateAPIToken(request, subject.apiGrant, now); err != nil {
			return deny(err, "api_token_denied")
		}
		return allow("api_token_scope")
	}
	if !hasTenantAccess(subject.principal, request.Target) {
		return deny(ErrCrossTenant, "cross_tenant_denied")
	}
	if !roleAllows(subject.principal, request.Action, request.Target) {
		return deny(ErrRoleDenied, "role_denied")
	}
	return allow(ruleForRole(subject.principal, request.Action, request.Target))
}

func (policy *Policy) resolveSubject(request AuthorizationRequest, authentication AuthenticationResult, authenticationErr error, now time.Time) (resolvedSubject, Decision) {
	subject := resolvedSubject{
		actor:      request.Subject.ID,
		authnClass: authentication.CredentialClass,
		mfa:        authentication.MFA,
		session:    authentication.Session,
		proof:      authentication.Proof,
	}
	if authenticationErr != nil || authentication.SubjectID == "" || authentication.SubjectID != request.Subject.ID {
		return subject, deny(ErrAuthentication, "authentication_required")
	}
	if request.BreakGlass {
		if authentication.CredentialClass != CredentialClassBreakGlass {
			return subject, deny(ErrAuthentication, "authentication_class_denied")
		}
	} else if request.SupportGrantRef != "" {
		if authentication.CredentialClass != CredentialClassSupportGrant {
			return subject, deny(ErrAuthentication, "authentication_class_denied")
		}
	} else if request.Subject.APITokenRef == "" && authentication.CredentialClass != CredentialClassInteractiveSession {
		return subject, deny(ErrAuthentication, "authentication_class_denied")
	}
	if request.Subject.APITokenRef != "" {
		if authentication.CredentialClass != CredentialClassShortLivedAPIToken || authentication.APITokenRef != request.Subject.APITokenRef {
			return subject, deny(ErrAuthentication, "authentication_class_denied")
		}
		apiGrant, ok := policy.APITokens[request.Subject.APITokenRef]
		if !ok || apiGrant.Reference != request.Subject.APITokenRef || apiGrant.SubjectID != authentication.SubjectID {
			subject.actor = "api-token-" + request.Subject.APITokenRef
			return subject, deny(ErrUnknownPrincipal, "fail_closed")
		}
		principal, ok := policy.Principals[apiGrant.SubjectID]
		if !ok || principal.ID != apiGrant.SubjectID {
			subject.actor = "api-grant:" + apiGrant.Reference
			return subject, deny(ErrUnknownPrincipal, "fail_closed")
		}
		subject = resolvedSubject{
			principal:   principal,
			actor:       "api-grant:" + apiGrant.Reference,
			represented: apiGrant.SubjectID,
			apiGrant:    apiGrant,
			authnClass:  authentication.CredentialClass,
			mfa:         authentication.MFA,
			session:     authentication.Session,
			proof:       authentication.Proof,
		}
		if !apiGrant.RevokedAt.IsZero() {
			return subject, deny(ErrTokenRevoked, "api_token_denied")
		}
		if apiGrant.ExpiresAt.IsZero() || !now.Before(apiGrant.ExpiresAt) {
			return subject, deny(ErrTokenExpired, "api_token_denied")
		}
		return subject, Decision{}
	}
	principal, ok := policy.Principals[request.Subject.ID]
	subject.principal = principal
	if !ok || principal.ID != request.Subject.ID {
		return subject, deny(ErrUnknownPrincipal, "fail_closed")
	}
	return subject, Decision{}
}

func (policy *Policy) resolveTarget(target TargetRef) (Tenant, Project, error) {
	organization, ok := policy.Organizations[target.OrgID]
	if !ok || organization.ID != target.OrgID {
		return Tenant{}, Project{}, ErrUnknownTenant
	}
	tenant, ok := policy.Tenants[target.TenantID]
	if !ok || tenant.ID != target.TenantID || tenant.OrgID != target.OrgID {
		return Tenant{}, Project{}, ErrUnknownTenant
	}
	project, ok := policy.Projects[target.ProjectID]
	if !ok || project.ID != target.ProjectID || project.TenantID != target.TenantID || project.OrgID != target.OrgID {
		return tenant, Project{}, ErrUnknownProject
	}
	return tenant, project, nil
}

func (policy *Policy) evaluateBreakGlass(request AuthorizationRequest, subject resolvedSubject) Decision {
	if strings.TrimSpace(request.Context.Reason) == "" {
		return deny(ErrReasonRequired, "break_glass_reason_required")
	}
	if strings.TrimSpace(request.Context.TicketRef) == "" {
		return deny(ErrTicketRequired, "break_glass_ticket_required")
	}
	if !roleAllows(subject.principal, ActionTenantRecover, request.Target) {
		return deny(ErrRoleDenied, "role_denied")
	}
	return allow("break_glass")
}

func (policy *Policy) evaluateSupportGrant(request AuthorizationRequest, subject resolvedSubject, now time.Time) Decision {
	grant, ok := policy.SupportGrants[request.SupportGrantRef]
	if !ok || grant.Reference != request.SupportGrantRef || grant.SubjectID != subject.principal.ID {
		return deny(ErrSupportGrant, "support_grant_denied")
	}
	if !subject.principal.Support {
		return deny(ErrSupportGrant, "support_grant_denied")
	}
	if strings.TrimSpace(request.Context.TicketRef) == "" || request.Context.TicketRef != grant.TicketRef {
		return deny(ErrTicketRequired, "support_ticket_required")
	}
	if strings.TrimSpace(request.Context.Reason) == "" || strings.TrimSpace(grant.Reason) == "" {
		return deny(ErrReasonRequired, "support_reason_required")
	}
	if grant.ExpiresAt.IsZero() || !now.Before(grant.ExpiresAt) {
		return deny(ErrSupportGrant, "support_grant_denied")
	}
	if grant.TenantID != request.Target.TenantID || grant.ProjectID != request.Target.ProjectID {
		return deny(ErrCrossTenant, "cross_tenant_denied")
	}
	if !actionAllowed(grant.Actions, request.Action) {
		return deny(ErrSupportGrant, "support_grant_denied")
	}
	return allow("support_grant")
}

func (policy *Policy) evaluateAPIToken(request AuthorizationRequest, token APIToken, now time.Time) error {
	if token.RevokedAt.IsZero() && !token.ExpiresAt.IsZero() && now.Before(token.ExpiresAt) {
		if token.TenantID != request.Target.TenantID || token.ProjectID != request.Target.ProjectID {
			return ErrCrossTenant
		}
		if token.SecretHashRef == "" || !actionAllowed(token.Scopes, request.Action) {
			return ErrTokenScope
		}
		return nil
	}
	if !token.RevokedAt.IsZero() {
		return ErrTokenRevoked
	}
	return ErrTokenExpired
}

func (policy *Policy) requestTime() time.Time {
	return policy.clock.Now().UTC()
}

func (policy *Policy) removingLastOwner(targetPrincipal string, project Project) bool {
	if targetPrincipal == "" {
		return true
	}
	identities := make(map[string]struct{}, len(policy.Principals))
	owners := make(map[string]struct{})
	for reference, principal := range policy.Principals {
		// The map key is the trusted identity reference. Malformed or duplicated
		// entity identity makes owner cardinality ambiguous, so removal fails closed.
		if reference == "" || principal.ID == "" || reference != principal.ID {
			return true
		}
		if _, duplicate := identities[principal.ID]; duplicate {
			return true
		}
		identities[principal.ID] = struct{}{}
		if principalOwns(principal, project) {
			owners[principal.ID] = struct{}{}
		}
	}
	_, targetOwns := owners[targetPrincipal]
	return !targetOwns || len(owners) <= 1
}

func allow(rule string) Decision {
	return Decision{Allowed: true, PolicyRule: rule}
}

func deny(err error, rule string) Decision {
	return Decision{Err: err, PolicyRule: rule}
}
