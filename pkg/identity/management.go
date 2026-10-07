// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package identity

type ManagementDecision struct {
	Authenticated bool
	TokenValid    bool
	IAMAllow      bool
	IAMErr        string
}

func ManagementPanelAllowed(decision ManagementDecision) bool {
	return decision.Authenticated && decision.TokenValid && decision.IAMAllow && decision.IAMErr == ""
}
