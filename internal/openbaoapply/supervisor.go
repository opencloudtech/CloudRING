// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package openbaoapply

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/opencloudtech/CloudRING/pkg/openbaoauth"
	"github.com/opencloudtech/CloudRING/pkg/openbaobootstrap"
)

const SupervisorSchemaVersion = "cloudring.openbao-kubernetes-auth-supervise/v1"

// SupervisorRequest is the single pipe-only input for the protected root
// delegation boundary. The temporary policy, wrapped child credential, and
// apply binding are generated inside the process.
type SupervisorRequest struct {
	SchemaVersion        string               `json:"schemaVersion"`
	Contract             openbaoauth.Contract `json:"contract"`
	OpenBao              Connection           `json:"openBao"`
	Kubernetes           Connection           `json:"kubernetes"`
	Lease                LeaseTarget          `json:"lease"`
	ExecutorIdentity     WorkloadIdentity     `json:"executorIdentity"`
	RootCredentialBase64 string               `json:"rootCredentialBase64"`
	Seed                 Seed                 `json:"seed"`
	NegativeIdentities   NegativeIdentities   `json:"negativeIdentities"`
	ChangeAuthorized     bool                 `json:"changeAuthorized"`
	rootCredential       []byte               `json:"-"`
}

type temporaryPolicyOwnership struct {
	name     string
	body     string
	modified string
}

// Supervise creates one exact temporary delegation, invokes the apply state
// machine in-process, and removes the temporary authority before returning.
func Supervise(ctx context.Context, reader io.Reader) (Report, error) {
	input, gate, err := parseSupervisorRequest(reader)
	if err != nil {
		return Report{}, err
	}
	if gate != "" {
		return fixedReport(StatusBlockedPreflight, false, false, gate, nil), nil
	}
	defer zeroBytes(input.rootCredential)
	policyName, err := randomPolicyName(rand.Reader)
	if err != nil {
		return fixedReport(StatusBlockedPreflight, false, false, "supervisor-randomness", nil), nil
	}
	validationRequest, gate := assembleSupervisedRequest(input, policyName, "validation-wrapper", "validation-child-accessor")
	if gate != "" {
		return fixedReport(StatusBlockedPreflight, false, false, gate, nil), nil
	}
	kubernetes, err := NewKubernetesClient(validationRequest.Kubernetes)
	if err != nil {
		return fixedReport(StatusBlockedPreflight, false, false, "secure-client", nil), nil
	}
	openBao, err := newSupervisorOpenBaoClient(validationRequest.OpenBao)
	if err != nil {
		return fixedReport(StatusBlockedPreflight, false, false, "secure-client", nil), nil
	}
	return executeSupervised(ctx, input, policyName, kubernetes, openBao), nil
}

func parseSupervisorRequest(reader io.Reader) (SupervisorRequest, string, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxInputBytes+1))
	if err != nil {
		return SupervisorRequest{}, "input-unavailable", errInputUnavailable
	}
	if len(data) > MaxInputBytes {
		return SupervisorRequest{}, "input-too-large", nil
	}
	if len(data) == 0 || !json.Valid(data) {
		return SupervisorRequest{}, "invalid-json", nil
	}
	duplicate, err := inspectJSONFields(data)
	if err != nil || duplicate {
		if duplicate {
			return SupervisorRequest{}, "duplicate-field", nil
		}
		return SupervisorRequest{}, "invalid-json", nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request SupervisorRequest
	if decoder.Decode(&request) != nil {
		return SupervisorRequest{}, "invalid-contract", nil
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return SupervisorRequest{}, "trailing-json", nil
	}
	if request.SchemaVersion != SupervisorSchemaVersion || !request.ChangeAuthorized {
		return SupervisorRequest{}, "supervisor-contract", nil
	}
	rootBytes, err := base64.StdEncoding.Strict().DecodeString(request.RootCredentialBase64)
	if err != nil || len(rootBytes) < 8 || len(rootBytes) > 64*1024 {
		zeroBytes(rootBytes)
		return SupervisorRequest{}, "root-credential-contract", nil
	}
	request.RootCredentialBase64 = ""
	request.rootCredential = rootBytes
	return request, "", nil
}

func randomPolicyName(reader io.Reader) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", err
	}
	name := "cloudring-bootstrap-" + hex.EncodeToString(value)
	zeroBytes(value)
	return name, nil
}

func assembleSupervisedRequest(input SupervisorRequest, policyName, wrapper, managementAccessor string) (Request, string) {
	request := Request{
		SchemaVersion: SchemaVersion, Contract: input.Contract, OpenBao: input.OpenBao, Kubernetes: input.Kubernetes,
		Lease: input.Lease, ExecutorIdentity: input.ExecutorIdentity, ManagementPolicyName: policyName, ManagementAccessor: managementAccessor,
		WrappingTokenBase64: base64.StdEncoding.EncodeToString([]byte(wrapper)), Seed: input.Seed,
		NegativeIdentities: input.NegativeIdentities, Approval: Approval{ChangeAuthorized: input.ChangeAuthorized},
	}
	binding, err := BindingSHA256(request)
	if err != nil {
		return Request{}, "approval-binding"
	}
	request.Approval.BindingSHA256 = binding
	if gate := validateRequest(&request); gate != "" {
		return Request{}, gate
	}
	return request, ""
}

func executeSupervised(ctx context.Context, input SupervisorRequest, policyName string, kubernetes KubernetesClient, openBao SupervisorOpenBaoClient) Report {
	completed := make([]string, 0, 8)
	rootBytes := input.rootCredential
	if len(rootBytes) == 0 {
		rootBytes, _ = base64.StdEncoding.Strict().DecodeString(input.RootCredentialBase64)
	}
	rootBearer := string(rootBytes)
	defer zeroBytes(rootBytes)
	if err := openBao.Health(ctx); err != nil {
		return fixedReport(StatusBlockedPreflight, false, false, "openbao-health", completed)
	}
	completed = append(completed, "openbao-active-unsealed")
	rootFacts, err := openBao.LookupInitialRoot(ctx, rootBearer)
	if err != nil || !validInitialRoot(rootFacts) {
		return fixedReport(StatusBlockedPreflight, false, false, "initial-root-profile", completed)
	}
	completed = append(completed, "initial-root-profile")
	delegation, err := openbaobootstrap.BuildManagementDelegation(input.Contract, policyName, input.Seed.RelativePath)
	if err != nil {
		return fixedReport(StatusBlockedPreflight, false, false, "management-policy-contract", completed)
	}
	preState, err := openBao.ReadTemporaryPolicy(ctx, rootBearer, policyName)
	if err != nil || preState.Found {
		return fixedReport(StatusBlockedPreflight, false, false, "temporary-policy-prestate", completed)
	}
	writeErr := openBao.CreateTemporaryPolicy(ctx, rootBearer, policyName, delegation.Body)
	policy, readErr := openBao.ReadTemporaryPolicy(ctx, rootBearer, policyName)
	modified, policyCreated := temporaryPolicyCreated(policy, policyName, delegation.Body)
	policyCreated = readErr == nil && policyCreated
	policyOwnership := temporaryPolicyOwnership{name: policyName, body: delegation.Body, modified: modified}
	if writeErr != nil || !policyCreated {
		if definitelyRejected(writeErr) && readErr == nil && !policy.Found {
			return fixedReport(StatusBlockedPreflight, false, false, "temporary-policy-create", completed)
		}
		if policyCreated {
			_ = cleanupTemporaryPolicy(context.WithoutCancel(ctx), openBao, rootBearer, policyOwnership)
		}
		return fixedReport(StatusPartialManualInterventionRequired, true, policyCreated, "temporary-policy-create", completed)
	}
	completed = append(completed, "temporary-management-policy")
	wrapped, err := openBao.CreateWrappedManagementToken(ctx, rootBearer, rootFacts.Accessor, policyName)
	if err != nil {
		cleaned := cleanupTemporaryPolicy(context.WithoutCancel(ctx), openBao, rootBearer, policyOwnership)
		if cleaned && definitelyRejected(err) {
			return fixedReport(StatusRolledBack, true, true, "wrapped-delegation-create", completed)
		}
		return fixedReport(StatusPartialManualInterventionRequired, true, true, chooseSupervisorGate(cleaned, "wrapped-delegation-create"), completed)
	}
	completed = append(completed, "wrapped-management-delegation")
	applyRequest, gate := assembleSupervisedRequest(input, policyName, wrapped.Value, wrapped.WrappedAccessor)
	if gate != "" {
		cleaned := cleanupSupervisorAuthority(context.WithoutCancel(ctx), openBao, rootBearer, policyOwnership, wrapped)
		return fixedReport(StatusPartialManualInterventionRequired, true, true, chooseSupervisorGate(cleaned, gate), completed)
	}
	applyReport := Execute(ctx, applyRequest, kubernetes, openBao.ApplyClient())
	cleaned := cleanupSupervisorAuthority(context.WithoutCancel(ctx), openBao, rootBearer, policyOwnership, wrapped)
	applyReport.MutationPerformed = true
	applyReport.RollbackAttempted = true
	if cleaned {
		applyReport.CompletedGates = append(applyReport.CompletedGates, "supervisor-authority-cleanup")
		if applyReport.Status == StatusBlockedPreflight {
			applyReport.Status = StatusRolledBack
		}
	} else {
		applyReport.Status = StatusPartialManualInterventionRequired
		applyReport.FailedGate = "supervisor-cleanup"
	}
	return applyReport
}

func validInitialRoot(facts TokenFacts) bool {
	return equalStrings(facts.Policies, []string{"root"}) && facts.Accessor != "" && facts.TTL == 0 && facts.ExplicitMaxTTL == 0 && !facts.RenewableKnown && !facts.Renewable && facts.Orphan &&
		facts.TokenType == "service" && facts.Path == "auth/token/root" && facts.NumUses == 0 && facts.MetadataEntries == 0 && facts.EntityID == "" &&
		len(facts.IdentityPolicies) == 0 && facts.ExternalNamespacePolicies == 0
}

func temporaryPolicyCreated(result ReadResult, name, body string) (string, bool) {
	version, versionOK := integer(result.Data, "version")
	modified := textValue(result.Data, "modified")
	return modified, exactManagementPolicy(result, name, body) && versionOK && version == 1
}

func cleanupTemporaryPolicy(ctx context.Context, client SupervisorOpenBaoClient, rootBearer string, ownership temporaryPolicyOwnership) bool {
	if ctx.Err() != nil {
		return false
	}
	current, err := client.ReadTemporaryPolicy(ctx, rootBearer, ownership.name)
	modified, exact := temporaryPolicyCreated(current, ownership.name, ownership.body)
	if err != nil || !exact || modified != ownership.modified {
		return false
	}
	_ = client.DeleteTemporaryPolicy(ctx, rootBearer, ownership.name)
	postState, err := client.ReadTemporaryPolicy(ctx, rootBearer, ownership.name)
	return err == nil && !postState.Found
}

func cleanupSupervisorAuthority(ctx context.Context, client SupervisorOpenBaoClient, rootBearer string, ownership temporaryPolicyOwnership, wrapped WrappedToken) bool {
	policyClean := cleanupTemporaryPolicy(ctx, client, rootBearer, ownership)
	wrapperClean := client.RevokeAccessorAndProve(ctx, rootBearer, wrapped.Accessor)
	childClean := client.RevokeAccessorAndProve(ctx, rootBearer, wrapped.WrappedAccessor)
	return policyClean && wrapperClean && childClean
}

func chooseSupervisorGate(cleaned bool, original string) string {
	if !cleaned {
		return "supervisor-cleanup"
	}
	return original
}
