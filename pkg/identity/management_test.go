// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package identity

import "testing"

func TestManagementUIDenyBeforeIAMAllow(t *testing.T) {
	for name, decision := range map[string]ManagementDecision{
		"anonymous":   {Authenticated: false, TokenValid: false, IAMAllow: false},
		"token error": {Authenticated: true, TokenValid: false, IAMAllow: true},
		"iam denied":  {Authenticated: true, TokenValid: true, IAMAllow: false},
		"iam errored": {Authenticated: true, TokenValid: true, IAMAllow: true, IAMErr: "policy backend unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			if ManagementPanelAllowed(decision) {
				t.Fatalf("management panel should remain hidden for %s", name)
			}
		})
	}
	if !ManagementPanelAllowed(ManagementDecision{Authenticated: true, TokenValid: true, IAMAllow: true}) {
		t.Fatal("management panel should be visible only after IAM allow")
	}
}
