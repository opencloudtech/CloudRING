// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package iam

type DeniedState struct {
	Code       string `json:"code"`
	Owner      string `json:"owner"`
	Impact     string `json:"impact"`
	NextAction string `json:"nextAction"`
}

func SessionRequiredDeniedState() DeniedState {
	return DeniedState{
		Code:       "session_required",
		Owner:      "platform-identity",
		Impact:     "The request stops before tenant or provider data is returned.",
		NextAction: "Authenticate with a valid CloudRING identity token and retry.",
	}
}

func TokenRejectedDeniedState() DeniedState {
	return DeniedState{
		Code:       "iam_token_rejected",
		Owner:      "platform-identity",
		Impact:     "The request is denied before any tenant, project, or provider surface is evaluated.",
		NextAction: "Refresh the short-lived credential from the trusted OIDC issuer and retry.",
	}
}

func ManagementDeniedState() DeniedState {
	return DeniedState{
		Code:       "management_denied_before_iam_allow",
		Owner:      "platform-security",
		Impact:     "Provider-only controls remain hidden and no management mutation is possible.",
		NextAction: "Ask a platform administrator to review the IAM role, tenant, project, and audit context.",
	}
}

func AuthUnavailableDeniedState() DeniedState {
	return DeniedState{
		Code:       "auth_not_configured",
		Owner:      "platform-identity",
		Impact:     "The surface is closed because no trusted authentication source is configured.",
		NextAction: "Verify bootstrap identity secret references and retry after IAM is healthy.",
	}
}
