// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package iam

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type PolicyState struct {
	Organizations map[string]Organization
	Tenants       map[string]Tenant
	Projects      map[string]Project
	Principals    map[string]Principal
	APITokens     map[string]APIToken
	SupportGrants map[string]SupportGrant
}

type PolicyStateLoader interface {
	Ready(context.Context) error
	LoadPolicyState(context.Context) (PolicyState, error)
}

// NewPolicyFromState is the production-oriented construction path. It requires
// a ready durable audit dependency, a trusted verifier with bounded proof
// policy, and a structurally consistent role/scope directory.
func NewPolicyFromState(ctx context.Context, config PolicyConfig, loader PolicyStateLoader) (*Policy, error) {
	if ctx == nil || loader == nil {
		return nil, errors.New("iam: policy state loader is required")
	}
	if config.AuthenticationVerifier == nil {
		return nil, errors.New("iam: authentication verifier is required")
	}
	if config.AuthenticationProofMaxAge <= 0 || config.AuthenticationProofMaxAge > 24*time.Hour ||
		config.AuthenticationProofFutureSkew < 0 || config.AuthenticationProofFutureSkew > 5*time.Minute {
		return nil, errors.New("iam: authentication proof bounds are invalid")
	}
	audit, ok := config.AuditSink.(DurableAuditSink)
	if !ok || !audit.Durable() || config.AllowEphemeralAudit {
		return nil, ErrAuditRequired
	}
	if err := audit.Ready(ctx); err != nil {
		return nil, fmt.Errorf("iam: audit dependency is unavailable: %w", ErrAuditRequired)
	}
	if err := loader.Ready(ctx); err != nil {
		return nil, fmt.Errorf("iam: policy state dependency is unavailable: %w", err)
	}
	state, err := loader.LoadPolicyState(ctx)
	if err != nil {
		return nil, fmt.Errorf("iam: load policy state: %w", err)
	}
	if err := validatePolicyState(state); err != nil {
		return nil, err
	}
	policy := NewPolicy(config)
	policy.Organizations = cloneOrganizations(state.Organizations)
	policy.Tenants = cloneTenants(state.Tenants)
	policy.Projects = cloneProjects(state.Projects)
	policy.Principals = clonePrincipals(state.Principals)
	policy.APITokens = cloneAPITokens(state.APITokens)
	policy.SupportGrants = cloneSupportGrants(state.SupportGrants)
	return policy, nil
}

func validatePolicyState(state PolicyState) error {
	if len(state.Organizations) == 0 || len(state.Tenants) == 0 ||
		len(state.Projects) == 0 || len(state.Principals) == 0 {
		return errors.New("iam: policy state requires organizations, tenants, projects, and principals")
	}
	for reference, organization := range state.Organizations {
		if reference == "" || organization.ID != reference {
			return errors.New("iam: organization reference mismatch")
		}
	}
	for reference, tenant := range state.Tenants {
		if reference == "" || tenant.ID != reference || tenant.OrgID == "" {
			return errors.New("iam: tenant reference mismatch")
		}
		if _, ok := state.Organizations[tenant.OrgID]; !ok || !knownTenantState(tenant.State) {
			return errors.New("iam: tenant organization or lifecycle is invalid")
		}
	}
	for reference, project := range state.Projects {
		tenant, tenantOK := state.Tenants[project.TenantID]
		if reference == "" || project.ID != reference || !tenantOK ||
			project.OrgID == "" || tenant.OrgID != project.OrgID || project.Namespace == "" {
			return errors.New("iam: project reference or tenant boundary is invalid")
		}
		for _, scope := range project.Scopes {
			if scope.Namespace == "" || len(scope.Actions) == 0 {
				return errors.New("iam: project namespace scope is invalid")
			}
			for _, action := range scope.Actions {
				if !knownAction(action) {
					return errors.New("iam: project namespace scope contains an unknown action")
				}
			}
		}
	}
	for reference, principal := range state.Principals {
		if reference == "" || principal.ID != reference {
			return errors.New("iam: principal reference mismatch")
		}
		for _, membership := range principal.Memberships {
			tenant, tenantOK := state.Tenants[membership.TenantID]
			if !tenantOK || tenant.OrgID != membership.OrgID || !knownRole(membership.Role) {
				return errors.New("iam: principal membership boundary is invalid")
			}
			if membership.ProjectID != "" {
				project, projectOK := state.Projects[membership.ProjectID]
				if !projectOK || project.TenantID != membership.TenantID || project.OrgID != membership.OrgID {
					return errors.New("iam: principal project membership is invalid")
				}
			}
		}
	}
	for reference, apiGrant := range state.APITokens {
		project, projectOK := state.Projects[apiGrant.ProjectID]
		if reference == "" || apiGrant.Reference != reference || apiGrant.SecretHashRef == "" ||
			state.Principals[apiGrant.SubjectID].ID != apiGrant.SubjectID || !projectOK ||
			project.TenantID != apiGrant.TenantID || len(apiGrant.Scopes) == 0 {
			return errors.New("iam: api token reference or scope is invalid")
		}
		for _, action := range apiGrant.Scopes {
			if !knownAction(action) {
				return errors.New("iam: api token contains an unknown action")
			}
		}
	}
	for reference, grant := range state.SupportGrants {
		project, projectOK := state.Projects[grant.ProjectID]
		if reference == "" || grant.Reference != reference ||
			state.Principals[grant.SubjectID].ID != grant.SubjectID || !projectOK ||
			project.TenantID != grant.TenantID || len(grant.Actions) == 0 {
			return errors.New("iam: support grant reference or scope is invalid")
		}
		for _, action := range grant.Actions {
			if !knownAction(action) {
				return errors.New("iam: support grant contains an unknown action")
			}
		}
	}
	return nil
}

func knownTenantState(state TenantState) bool {
	switch state {
	case TenantStateActive, TenantStateSuspended, TenantStateDeleting, TenantStateRecovering, TenantStateExporting:
		return true
	default:
		return false
	}
}

func knownRole(role Role) bool {
	switch role {
	case RoleOwner, RoleTenantAdmin, RoleTenantViewer, RoleSupport, RolePlatformAdmin:
		return true
	default:
		return false
	}
}

func cloneOrganizations(values map[string]Organization) map[string]Organization {
	cloned := make(map[string]Organization, len(values))
	for reference, value := range values {
		cloned[reference] = value
	}
	return cloned
}

func cloneTenants(values map[string]Tenant) map[string]Tenant {
	cloned := make(map[string]Tenant, len(values))
	for reference, value := range values {
		cloned[reference] = value
	}
	return cloned
}

func cloneProjects(values map[string]Project) map[string]Project {
	cloned := make(map[string]Project, len(values))
	for reference, value := range values {
		value.Scopes = append([]NamespaceScope{}, value.Scopes...)
		for index := range value.Scopes {
			value.Scopes[index].Actions = append([]Action{}, value.Scopes[index].Actions...)
		}
		cloned[reference] = value
	}
	return cloned
}

func clonePrincipals(values map[string]Principal) map[string]Principal {
	cloned := make(map[string]Principal, len(values))
	for reference, value := range values {
		value.Groups = append([]string{}, value.Groups...)
		value.Memberships = append([]Membership{}, value.Memberships...)
		cloned[reference] = value
	}
	return cloned
}

func cloneAPITokens(values map[string]APIToken) map[string]APIToken {
	cloned := make(map[string]APIToken, len(values))
	for reference, value := range values {
		value.Scopes = append([]Action{}, value.Scopes...)
		cloned[reference] = value
	}
	return cloned
}

func cloneSupportGrants(values map[string]SupportGrant) map[string]SupportGrant {
	cloned := make(map[string]SupportGrant, len(values))
	for reference, value := range values {
		value.Actions = append([]Action{}, value.Actions...)
		cloned[reference] = value
	}
	return cloned
}
