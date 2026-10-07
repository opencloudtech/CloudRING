// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package iam

func evaluateAssurance(request AuthorizationRequest, subject resolvedSubject) Decision {
	mfa := normalizedMFA(request, subject.authnClass, subject.mfa)
	if mfa.Required && (!mfa.Satisfied || !knownSatisfiedMFAMethod(mfa.MethodClass)) {
		return deny(ErrMFARequired, "mfa_required")
	}

	if subject.authnClass == CredentialClassShortLivedAPIToken {
		if subject.session.State != SessionStateAbsent || subject.session.MaxAgeSeconds != 0 || subject.session.ReauthenticationRequired {
			return deny(ErrSessionAssurance, "session_assurance_denied")
		}
		return Decision{}
	}
	if subject.session.State != SessionStateFresh || subject.session.MaxAgeSeconds <= 0 || subject.session.ReauthenticationRequired {
		return deny(ErrSessionAssurance, "session_assurance_denied")
	}
	return Decision{}
}

func principalRequiresMFA(principal Principal) bool {
	if principal.Support {
		return true
	}
	for _, membership := range principal.Memberships {
		if membership.Role == RolePlatformAdmin {
			return true
		}
	}
	return false
}

func knownSatisfiedMFAMethod(method MFAMethodClass) bool {
	switch method {
	case MFAMethodTOTP, MFAMethodWebAuthn, MFAMethodHardwareKey, MFAMethodExternalIDP:
		return true
	default:
		return false
	}
}

func normalizedMFA(request AuthorizationRequest, credential CredentialClass, mfa MFAAssurance) MFAAssurance {
	if credential != CredentialClassShortLivedAPIToken && (request.Action != ActionProjectRead || request.SupportGrantRef != "" || request.BreakGlass) {
		mfa.Required = true
	}
	return mfa
}

func knownAction(action Action) bool {
	switch action {
	case ActionProjectRead, ActionProjectWrite, ActionProjectManage, ActionOwnerRemove, ActionTenantExport, ActionTenantRecover:
		return true
	default:
		return false
	}
}

func lifecycleAllows(state TenantState, action Action) error {
	switch state {
	case TenantStateActive:
		return nil
	case TenantStateSuspended:
		if action == ActionTenantExport || action == ActionTenantRecover || action == ActionProjectRead {
			return nil
		}
		return ErrTenantSuspended
	case TenantStateDeleting:
		if action == ActionTenantExport || action == ActionProjectRead {
			return nil
		}
		return ErrTenantDeleting
	case TenantStateRecovering:
		if action == ActionTenantRecover || action == ActionProjectRead {
			return nil
		}
		return ErrTenantSuspended
	case TenantStateExporting:
		if action == ActionTenantExport || action == ActionProjectRead {
			return nil
		}
		return ErrTenantSuspended
	default:
		return ErrTenantState
	}
}

func hasTenantAccess(principal Principal, target TargetRef) bool {
	for _, membership := range principal.Memberships {
		if membership.Role == RolePlatformAdmin {
			return true
		}
		if membership.OrgID == target.OrgID && membership.TenantID == target.TenantID {
			if membership.ProjectID == "" || membership.ProjectID == target.ProjectID {
				return true
			}
		}
	}
	return false
}

func roleAllows(principal Principal, action Action, target TargetRef) bool {
	for _, membership := range principal.Memberships {
		if membership.Role == RolePlatformAdmin {
			return true
		}
		if membership.OrgID != target.OrgID || membership.TenantID != target.TenantID {
			continue
		}
		if membership.ProjectID != "" && membership.ProjectID != target.ProjectID {
			continue
		}
		if membershipRoleAllows(membership.Role, action) {
			return true
		}
	}
	return false
}

func targetWithinProjectScope(target TargetRef, project Project, action Action) bool {
	if target.Namespace == "" {
		return false
	}
	if project.Namespace != "" && target.Namespace == project.Namespace {
		return true
	}
	for _, scope := range project.Scopes {
		if scope.Namespace == target.Namespace && actionAllowed(scope.Actions, action) {
			return true
		}
	}
	return false
}

func membershipRoleAllows(role Role, action Action) bool {
	switch role {
	case RoleOwner:
		return action == ActionProjectRead ||
			action == ActionProjectWrite ||
			action == ActionProjectManage ||
			action == ActionOwnerRemove
	case RoleTenantAdmin:
		return action == ActionProjectRead ||
			action == ActionProjectWrite ||
			action == ActionProjectManage
	case RoleTenantViewer:
		return action == ActionProjectRead
	case RoleSupport:
		return action == ActionProjectRead
	case RolePlatformAdmin:
		return true
	default:
		return false
	}
}

func ruleForRole(principal Principal, action Action, target TargetRef) string {
	for _, membership := range principal.Memberships {
		if membership.Role == RolePlatformAdmin {
			return "platform_admin_lifecycle"
		}
		if membership.OrgID != target.OrgID || membership.TenantID != target.TenantID {
			continue
		}
		if membership.ProjectID != "" && membership.ProjectID != target.ProjectID {
			continue
		}
		if membership.Role == RoleTenantAdmin && action == ActionProjectManage {
			return "tenant_admin_project_manage"
		}
		if membershipRoleAllows(membership.Role, action) {
			return string(membership.Role)
		}
	}
	return "role_denied"
}

func actionAllowed(actions []Action, want Action) bool {
	for _, action := range actions {
		if action == want {
			return true
		}
	}
	return false
}

func sameProject(membership Membership, project Project) bool {
	return membership.OrgID == project.OrgID &&
		membership.TenantID == project.TenantID &&
		membership.ProjectID == project.ID
}

func principalOwns(principal Principal, project Project) bool {
	for _, membership := range principal.Memberships {
		if membership.Role == RoleOwner && sameProject(membership, project) {
			return true
		}
	}
	return false
}
