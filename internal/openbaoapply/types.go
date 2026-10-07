// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

// Package openbaoapply executes the fail-closed OpenBao Kubernetes-auth plan.
// Credentials are accepted only through the bounded stdin request and are
// retained in memory. Reports contain fixed policy facts only.
package openbaoapply

import (
	"context"
	"encoding/json"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/openbaoauth"
)

const (
	SchemaVersion = "cloudring.openbao-kubernetes-auth-apply/v1"
	MaxInputBytes = 512 * 1024

	StatusBlockedPreflight                  Status = "blocked_preflight"
	StatusApplied                           Status = "applied"
	StatusRolledBack                        Status = "rolled_back"
	StatusPartialManualInterventionRequired Status = "partial_manual_intervention_required"
)

// Status is deliberately a closed, evidence-safe result set.
type Status string

// Request is the complete one-shot apply input. All *Base64 fields may contain
// credentials and must never be copied to reports, errors, argv, environment,
// files, or logs.
type Request struct {
	SchemaVersion             string               `json:"schemaVersion"`
	Contract                  openbaoauth.Contract `json:"contract"`
	OpenBao                   Connection           `json:"openBao"`
	Kubernetes                Connection           `json:"kubernetes"`
	Lease                     LeaseTarget          `json:"lease"`
	ExecutorIdentity          WorkloadIdentity     `json:"executorIdentity"`
	ManagementPolicyName      string               `json:"managementPolicyName"`
	ManagementAccessor        string               `json:"managementAccessor"`
	WrappingTokenBase64       string               `json:"wrappingTokenBase64"`
	Seed                      Seed                 `json:"seed"`
	NegativeIdentities        NegativeIdentities   `json:"negativeIdentities"`
	Approval                  Approval             `json:"approval"`
	ExecutorServiceAccountUID string               `json:"-"`
}

// Connection pins one HTTPS API authority and its trust material.
type Connection struct {
	Address             string `json:"address"`
	ServerName          string `json:"serverName"`
	CACertificateBase64 string `json:"caCertificateBase64"`
	BearerTokenBase64   string `json:"bearerTokenBase64,omitempty"`
}

// LeaseTarget identifies a pre-created coordination.k8s.io/v1 Lease. The
// executor never creates, deletes, patches, or automatically takes over it.
type LeaseTarget struct {
	Namespace      string `json:"namespace"`
	Name           string `json:"name"`
	HolderIdentity string `json:"holderIdentity"`
}

// Seed is one create-only KV-v2 value below Contract.DataPrefix.
type Seed struct {
	RelativePath string        `json:"relativePath"`
	Entries      []SecretEntry `json:"entries"`
}

// NegativeIdentities are pre-created, token-request-capable identities used to
// prove that the role is bound to both the exact ServiceAccount and namespace.
type NegativeIdentities struct {
	WrongServiceAccount WorkloadIdentity `json:"wrongServiceAccount"`
	WrongNamespace      WorkloadIdentity `json:"wrongNamespace"`
}

type WorkloadIdentity struct {
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
}

// SecretEntry keeps secret bytes encoded while crossing the JSON boundary.
type SecretEntry struct {
	Key         string `json:"key"`
	ValueBase64 string `json:"valueBase64"`
}

// Approval is an execution-consistency assertion made by an already-authorized
// protected supervisor. It is not a standalone authorization receipt.
type Approval struct {
	ChangeAuthorized bool   `json:"changeAuthorized"`
	BindingSHA256    string `json:"bindingSHA256"`
}

// Report never contains identifiers, endpoints, fingerprints, or dynamic
// provider errors. Gate IDs are fixed public vocabulary.
type Report struct {
	SchemaVersion       string   `json:"schemaVersion"`
	Status              Status   `json:"status"`
	MutationPerformed   bool     `json:"mutationPerformed"`
	RollbackAttempted   bool     `json:"rollbackAttempted"`
	InputMaterialEchoed bool     `json:"inputMaterialEchoed"`
	CompletedGates      []string `json:"completedGates,omitempty"`
	FailedGate          string   `json:"failedGate,omitempty"`
	NonClaims           []string `json:"nonClaims"`
}

// Lease is the narrow representation required for resourceVersion-guarded
// coordination. Unknown API fields are preserved by the concrete REST client.
type Lease struct {
	Name             string
	Namespace        string
	UID              string
	ResourceVersion  string
	HolderIdentity   string
	LeaseDurationSec int32
	AcquireTime      time.Time
	RenewTime        time.Time
	Raw              json.RawMessage
}

// KubernetesClient is intentionally narrower than client-go.
type KubernetesClient interface {
	GetLease(context.Context, LeaseTarget) (Lease, error)
	UpdateLease(context.Context, LeaseTarget, Lease) (Lease, error)
	ReviewSelf(context.Context) (SubjectFacts, error)
	ReviewAccess(context.Context, ResourceAccess) (bool, error)
	GetServiceAccount(context.Context, string, string) (ServiceAccountFacts, error)
	RequestServiceAccountToken(context.Context, string, string, string, int64) (ServiceAccountToken, error)
}

type ServiceAccountFacts struct {
	UID string
}

type ServiceAccountToken struct {
	JWT                 string
	ExpirationTimestamp time.Time
}

type SubjectFacts struct {
	Username string
	UID      string
	Groups   []string
}

type ResourceAccess struct {
	Verb        string
	Group       string
	Resource    string
	Subresource string
	Namespace   string
	Name        string
}

// OpenBaoClient is intentionally expressed as exact operations, not a generic
// path client available to the state machine.
type OpenBaoClient interface {
	Unwrap(context.Context, string) (string, error)
	LookupSelf(context.Context, string) (TokenFacts, error)
	CapabilitiesSelf(context.Context, string, []string) (map[string][]string, error)
	Read(context.Context, string, string) (ReadResult, error)
	List(context.Context, string, string) (ReadResult, error)
	Write(context.Context, string, string, any) (ReadResult, error)
	Delete(context.Context, string, string) error
	Health(context.Context) error
	ExpectForbidden(context.Context, string, string, string, any) error
}

type SupervisorOpenBaoClient interface {
	ApplyClient() OpenBaoClient
	Health(context.Context) error
	LookupInitialRoot(context.Context, string) (TokenFacts, error)
	ReadTemporaryPolicy(context.Context, string, string) (ReadResult, error)
	CreateTemporaryPolicy(context.Context, string, string, string) error
	DeleteTemporaryPolicy(context.Context, string, string) error
	CreateWrappedManagementToken(context.Context, string, string, string) (WrappedToken, error)
	RevokeAccessorAndProve(context.Context, string, string) bool
}

type WrappedToken struct {
	Value           string
	Accessor        string
	WrappedAccessor string
	CreationPath    string
}

type TokenFacts struct {
	Policies                  []string
	Accessor                  string
	IdentityPolicies          []string
	ExternalNamespacePolicies int
	EntityID                  string
	Path                      string
	TTL                       int64
	ExplicitMaxTTL            int64
	NumUses                   int64
	MetadataEntries           int
	Renewable                 bool
	RenewableKnown            bool
	Orphan                    bool
	TokenType                 string
}

type ReadResult struct {
	Found bool
	Data  map[string]any
	Auth  map[string]any
}
