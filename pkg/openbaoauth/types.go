// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Package openbaoauth defines the source-only CloudRING contract for planning
// least-privilege OpenBao Kubernetes authentication. It never performs network
// requests or writes operator input to disk.
package openbaoauth

const (
	// SchemaVersion identifies the dedicated-mount CloudRING OpenBao
	// Kubernetes-auth plan. Version 2 replaces the unsafe v1 assumption that an
	// absent config on an existing auth mount could be rolled back.
	SchemaVersion = "cloudring.openbao-kubernetes-auth-plan/v2"
	// DedicatedAuthMountOwnership requires one auth mount per independently
	// managed workload boundary and allows config creation only when the same
	// execution created the mount. It is deliberately the only supported mode.
	DedicatedAuthMountOwnership = "dedicated-create-owned"
	// MaxInputBytes bounds stdin before decoding.
	MaxInputBytes = 64 * 1024
)

// Contract is the complete non-secret input for one workload identity.
type Contract struct {
	SchemaVersion        string           `json:"schemaVersion"`
	AuthMount            string           `json:"authMount"`
	AuthMountOwnership   string           `json:"authMountOwnership"`
	KVV2Mount            string           `json:"kvV2Mount"`
	DataPrefix           string           `json:"dataPrefix"`
	PolicyName           string           `json:"policyName"`
	RoleName             string           `json:"roleName"`
	WorkloadIdentity     WorkloadIdentity `json:"workloadIdentity"`
	Audience             string           `json:"audience"`
	AliasNameSource      string           `json:"aliasNameSource"`
	TokenTTL             string           `json:"tokenTTL"`
	TokenMaxTTL          string           `json:"tokenMaxTTL"`
	TokenNoDefaultPolicy bool             `json:"tokenNoDefaultPolicy"`
}

// WorkloadIdentity binds an OpenBao role to exactly one Kubernetes identity.
type WorkloadIdentity struct {
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
}

// Problem is a stable, evidence-safe validation result. Message text and
// operator-provided values are deliberately absent.
type Problem struct {
	Path string `json:"path"`
	Code string `json:"code"`
}

// Plan is a typed desired-state plan. It is intentionally not serialized by
// the CLI because it contains provider/site identifiers.
type Plan struct {
	AuthMountOwnership string
	AuthMountStates    []AuthMountStateRule
	MutationGate       MutationGate
	KVV2Mount          KVV2MountDesired
	AuthMount          AuthMountDesired
	AuthConfig         KubernetesConfigDesired
	AuthConfigReadback KubernetesConfigReadbackExpected
	ACLPolicy          ACLPolicyDesired
	Role               KubernetesRoleDesired
	Actions            []Action
}

// KVV2MountDesired is the only shared secret-engine shape the protected
// supervisor may initialize. An absent mount may be enabled create-only; an
// existing mount must match this shape exactly.
type KVV2MountDesired struct {
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Options     map[string]string `json:"options"`
}

// MutationGate binds every mutating action to the normalized auth-mount
// lifecycle decision. Blocked lifecycle states permit no write anywhere in
// the plan, including policy and role endpoints.
type MutationGate struct {
	ID               string
	AllowedDecisions []AuthMountDecision
}

// AuthMountStateRule is the complete fail-closed lifecycle table an executor
// must use before any OpenBao mutation. State names are fixed public policy
// terms and contain no provider identifiers.
type AuthMountStateRule struct {
	PreState     AuthMountPreState
	Decision     AuthMountDecision
	Mutates      bool
	RollbackMode string
}

// AuthMountPreState is the normalized state observed under the exclusive
// operator lock before a mount/config mutation decision.
type AuthMountPreState string

const (
	AuthMountAbsent                                AuthMountPreState = "absent"
	AuthMountPresentExact                          AuthMountPreState = "present-exact-type-contract-bound-description-config-and-no-foreign-roles"
	AuthMountPresentConfigAbsent                   AuthMountPreState = "present-config-absent"
	AuthMountPresentConfigDrifted                  AuthMountPreState = "present-config-drifted"
	AuthMountPresentTypeOrDescDrift                AuthMountPreState = "present-non-kubernetes-or-description-drifted"
	AuthMountUnknownIncompleteUnavailableOrChanged AuthMountPreState = "unknown-incomplete-unavailable-or-changed"
)

// AuthMountDecision is the only allowed lifecycle outcome for a normalized
// pre-state.
type AuthMountDecision string

const (
	AuthMountCreateOwned AuthMountDecision = "create-and-configure-current-run-owned"
	AuthMountReuseExact  AuthMountDecision = "reuse-without-mutation"
	AuthMountBlock       AuthMountDecision = "block-before-mutation"
)

// AuthMountDesired describes the supported OpenBao auth mount type.
type AuthMountDesired struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// KubernetesConfigDesired uses only OpenBao's rotating pod-local reviewer
// token and CA. No credential material is accepted by Contract.
type KubernetesConfigDesired struct {
	KubernetesHost       string   `json:"kubernetes_host"`
	KubernetesCACert     string   `json:"kubernetes_ca_cert"`
	TokenReviewerJWT     string   `json:"token_reviewer_jwt"`
	PEMKeys              []string `json:"pem_keys"`
	Issuer               string   `json:"issuer"`
	DisableISSValidation bool     `json:"disable_iss_validation"`
	DisableLocalCAJWT    bool     `json:"disable_local_ca_jwt"`
}

// KubernetesConfigReadbackExpected is the complete non-secret OpenBao 2.5.5
// config readback. TokenReviewerJWTSet is a read-only API fact and therefore
// is deliberately not part of the POST body above.
type KubernetesConfigReadbackExpected struct {
	KubernetesHost       string   `json:"kubernetes_host"`
	KubernetesCACert     string   `json:"kubernetes_ca_cert"`
	PEMKeys              []string `json:"pem_keys"`
	Issuer               string   `json:"issuer"`
	DisableISSValidation bool     `json:"disable_iss_validation"`
	DisableLocalCAJWT    bool     `json:"disable_local_ca_jwt"`
	TokenReviewerJWTSet  bool     `json:"token_reviewer_jwt_set"`
}

// ACLPolicyDesired is one read-only KV-v2 policy.
type ACLPolicyDesired struct {
	Policy      string `json:"policy"`
	CAS         int    `json:"cas"`
	CASRequired bool   `json:"cas_required"`
}

// KubernetesRoleDesired is an exact, non-wildcard workload role.
type KubernetesRoleDesired struct {
	BoundServiceAccountNames             []string `json:"bound_service_account_names"`
	BoundServiceAccountNamespaces        []string `json:"bound_service_account_namespaces"`
	BoundServiceAccountNamespaceSelector string   `json:"bound_service_account_namespace_selector"`
	Audience                             string   `json:"audience"`
	AliasNameSource                      string   `json:"alias_name_source"`
	TokenPolicies                        []string `json:"token_policies"`
	TokenNoDefaultPolicy                 bool     `json:"token_no_default_policy"`
	TokenTTL                             string   `json:"token_ttl"`
	TokenMaxTTL                          string   `json:"token_max_ttl"`
	TokenExplicitMaxTTL                  string   `json:"token_explicit_max_ttl"`
	TokenType                            string   `json:"token_type"`
	TokenNumUses                         int      `json:"token_num_uses"`
	TokenPeriod                          int      `json:"token_period"`
	TokenBoundCIDRs                      []string `json:"token_bound_cidrs"`
	TokenStrictlyBindIP                  bool     `json:"token_strictly_bind_ip"`
}

// Action is one preflight or conditional mutation in the ordered plan.
type Action struct {
	ID                     string
	Method                 string
	EndpointClass          string
	Target                 string
	Mutates                bool
	Conditional            bool
	PreStateRequired       bool
	RollbackRequired       bool
	RunCondition           string
	GlobalMutationGate     string
	MutationGuard          string
	RollbackMode           string
	CASMode                string
	DesiredState           any
	FailClosedPrecondition string
	ChangeRequiresApproval bool
}

// Report is the only form emitted by the CLI. It contains hashes and fixed
// policy facts, never raw identifiers, paths, HCL, endpoints, or input text.
type Report struct {
	SchemaVersion                 string          `json:"schemaVersion"`
	Mode                          string          `json:"mode"`
	Status                        string          `json:"status"`
	MutationPerformed             bool            `json:"mutationPerformed"`
	ApplyAuthorized               bool            `json:"applyAuthorized"`
	ApplyApprovalNeeded           bool            `json:"applyApprovalNeeded"`
	InputMaterialEchoed           bool            `json:"inputMaterialEchoed"`
	IdentifierFingerprintsEmitted bool            `json:"identifierFingerprintsEmitted"`
	Profile                       ProfileSummary  `json:"profile"`
	Actions                       []ActionSummary `json:"actions,omitempty"`
	Blockers                      []Problem       `json:"blockers,omitempty"`
	RequiredLiveGates             []string        `json:"requiredLiveGates"`
	NonClaims                     []string        `json:"nonClaims"`
}

// ProfileSummary contains only fixed CloudRING v2 policy values. It contains
// no contract-provided identifiers.
type ProfileSummary struct {
	AuthType             string   `json:"authType"`
	AuthMountOwnership   string   `json:"authMountOwnership"`
	KubernetesHostMode   string   `json:"kubernetesHostMode"`
	ReviewerSourceMode   string   `json:"reviewerSourceMode"`
	Audience             string   `json:"audience"`
	AliasNameSource      string   `json:"aliasNameSource"`
	Capabilities         []string `json:"capabilities"`
	BoundIdentityCount   int      `json:"boundIdentityCount"`
	TokenTTL             string   `json:"tokenTtl"`
	TokenMaxTTL          string   `json:"tokenMaxTtl"`
	TokenNoDefaultPolicy bool     `json:"tokenNoDefaultPolicy"`
}

// ActionSummary is the evidence-safe projection of Action.
type ActionSummary struct {
	ID                     string `json:"id"`
	Method                 string `json:"method"`
	EndpointClass          string `json:"endpointClass"`
	Mutates                bool   `json:"mutates"`
	Conditional            bool   `json:"conditional"`
	PreStateRequired       bool   `json:"preStateRequired"`
	RollbackRequired       bool   `json:"rollbackRequired"`
	RunCondition           string `json:"runCondition,omitempty"`
	GlobalMutationGate     string `json:"globalMutationGate,omitempty"`
	MutationGuard          string `json:"mutationGuard,omitempty"`
	RollbackMode           string `json:"rollbackMode,omitempty"`
	CASMode                string `json:"casMode"`
	FailClosedPrecondition string `json:"failClosedPrecondition,omitempty"`
	ChangeApprovalRequired bool   `json:"changeApprovalRequired"`
}
