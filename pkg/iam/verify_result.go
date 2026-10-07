// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package iam

import (
	"errors"
	"fmt"
	"sort"

	"github.com/opencloudtech/CloudRING/internal/privateartifact"
)

func writeVerifyEvidence(path string, report VerifyReport) error {
	if path == "" {
		return nil
	}
	if err := privateartifact.WriteNewJSON(path, report); err != nil {
		return fmt.Errorf("write iam evidence: %w", err)
	}
	return nil
}

func normalizeBlockers(blockers []VerifyBlocker) []VerifyBlocker {
	sort.Slice(blockers, func(i, j int) bool {
		return blockers[i].ID < blockers[j].ID
	})
	return blockers
}

func blockersToCases(blockers []VerifyBlocker) []VerifyCase {
	cases := make([]VerifyCase, 0, len(blockers))
	for _, blocker := range blockers {
		cases = append(cases, blocker.caseResult())
	}
	return cases
}

func (blocker VerifyBlocker) caseResult() VerifyCase {
	return VerifyCase{
		ID:               blocker.ID,
		Expected:         blocker.Expected,
		Observed:         blocker.Observed,
		PolicyRule:       blocker.PolicyRule,
		Error:            errorMessage(blocker.Err),
		Audited:          blocker.Audited,
		ReadinessClaimed: blocker.ReadinessClaimed,
		Executable:       blocker.Executable,
	}
}

func tokenSecretRefsOnly(policy *Policy) bool {
	for _, apiGrant := range policy.APITokens {
		if apiGrant.SecretHashRef == "" {
			return false
		}
	}
	return true
}

func verifyAllowed(id string, policy *Policy, request AuthorizationRequest) VerifyBlocker {
	decision := policy.Authorize(request)
	if decision.Allowed {
		return VerifyBlocker{ID: id, Message: "allow observed", Expected: "allow", Observed: "allow", PolicyRule: decision.PolicyRule, Audited: true, Executable: true}
	}
	return VerifyBlocker{ID: id, Message: "expected allow was denied", Expected: "allow", Observed: "deny", PolicyRule: decision.PolicyRule, Audited: true, Err: decision.Err, Executable: true}
}

func verifyDenied(id string, want error, policy *Policy, request AuthorizationRequest) VerifyBlocker {
	decision := policy.Authorize(request)
	if decision.Allowed {
		return VerifyBlocker{ID: id, Message: "expected deny was allowed", Expected: "deny", Observed: "allow", PolicyRule: decision.PolicyRule, Audited: true, Executable: true}
	}
	if !errors.Is(decision.Err, want) {
		return VerifyBlocker{ID: id, Message: "expected deny error was not observed", Expected: "deny", Observed: "deny", PolicyRule: decision.PolicyRule, Audited: true, Err: decision.Err, Executable: true}
	}
	return VerifyBlocker{ID: id, Message: "deny observed", Expected: "deny", Observed: "deny", PolicyRule: decision.PolicyRule, Audited: true, Err: decision.Err, Executable: true}
}

func failClosedBlocker(id string, message string, rule string) VerifyBlocker {
	return VerifyBlocker{ID: id, Message: message, Expected: "deny", Observed: "deny", PolicyRule: rule, Audited: true, Executable: true}
}

func errorMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
