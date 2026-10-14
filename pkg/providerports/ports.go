// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Package providerports defines the provider-neutral hexagonal port interfaces
// between the CloudRING Open Cloud Standard (OCS v3) domain kernel and
// downstream infrastructure adapters (KubeVirt, OpenStack, Proxmox, Bare-Metal)
// without coupling the domain core to Kubernetes or vendor client libraries.
package providerports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

const (
	ProvisionRequestSchemaVersion = "cloudring.provider-ports.provision-request/v1"
	ProvisionReceiptSchemaVersion = "cloudring.provider-ports.provision-receipt/v1"
	commitmentDomainPrefix        = "cloudring/provider-ports/commitment/v1"

	MaxParametersCount = 64
	MaxParameterValue  = 1024
)

// ServiceCategory enumerates the nine canonical CloudRING / OCS v3 product categories.
type ServiceCategory string

const (
	ServiceCompute             ServiceCategory = "compute"
	ServiceVolume              ServiceCategory = "volume"
	ServiceNetwork             ServiceCategory = "network"
	ServiceKubernetes          ServiceCategory = "kubernetes"
	ServiceObjectStorage       ServiceCategory = "object-storage"
	ServiceBackup              ServiceCategory = "backup"
	ServiceAccessControl       ServiceCategory = "access-control"
	ServiceSupport             ServiceCategory = "support"
	ServiceExternalIntegration ServiceCategory = "external-integration"
)

// BackendFamily identifies the infrastructure substrate family behind a port adapter.
type BackendFamily string

const (
	BackendKubeVirt  BackendFamily = "kubevirt"
	BackendOpenStack BackendFamily = "openstack"
	BackendProxmox   BackendFamily = "proxmox"
	BackendBareMetal BackendFamily = "bare-metal"
)

// LifecycleVerb enumerates the canonical OCS v3 resource lifecycle operations.
type LifecycleVerb string

const (
	VerbProvision   LifecycleVerb = "provision"
	VerbResume      LifecycleVerb = "resume"
	VerbResize      LifecycleVerb = "resize"
	VerbHold        LifecycleVerb = "hold"
	VerbSuspend     LifecycleVerb = "suspend"
	VerbDeprovision LifecycleVerb = "deprovision"
)

// ResourceState represents the canonical provider-neutral lifecycle state of a resource.
type ResourceState string

const (
	StatePending        ResourceState = "pending"
	StateProvisioning   ResourceState = "provisioning"
	StateReady          ResourceState = "ready"
	StateDegraded       ResourceState = "degraded"
	StateSuspended      ResourceState = "suspended"
	StateDeprovisioning ResourceState = "deprovisioning"
	StateDeleted        ResourceState = "deleted"
	StateFailed         ResourceState = "failed"
	StateDenied         ResourceState = "denied"
	StateBlocked        ResourceState = "blocked"
	StateRetryable      ResourceState = "retryable"
)

// HealthStatus represents the operational readiness of a provider port adapter.
type HealthStatus string

const (
	HealthReady       HealthStatus = "ready"
	HealthDegraded    HealthStatus = "degraded"
	HealthUnavailable HealthStatus = "unavailable"
)

var (
	ErrInvalidRequest           = errors.New("providerports: invalid provision request")
	ErrInvalidReceipt           = errors.New("providerports: invalid provision receipt")
	ErrInvalidHealthStatus      = errors.New("providerports: invalid health status")
	ErrInvalidAdapterDescriptor = errors.New("providerports: invalid adapter descriptor")
	ErrAdapterAlreadyRegistered = errors.New("providerports: adapter already registered")
	ErrAdapterNotFound          = errors.New("providerports: adapter not found")
	ErrIdempotencyConflict      = errors.New("providerports: idempotency key reused with different request parameters")
	ErrTenantIsolationViolation = errors.New("providerports: cross-tenant or cross-project access denied")
	ErrResourceNotFound         = errors.New("providerports: resource not found")
	ErrContextCanceled          = errors.New("providerports: operation canceled by caller context")

	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$`)
	paramKeyPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,62}$`)
	digestPattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)

	allServiceCategories = []ServiceCategory{
		ServiceCompute,
		ServiceVolume,
		ServiceNetwork,
		ServiceKubernetes,
		ServiceObjectStorage,
		ServiceBackup,
		ServiceAccessControl,
		ServiceSupport,
		ServiceExternalIntegration,
	}

	allBackendFamilies = []BackendFamily{
		BackendKubeVirt,
		BackendOpenStack,
		BackendProxmox,
		BackendBareMetal,
	}

	allLifecycleVerbs = []LifecycleVerb{
		VerbProvision,
		VerbResume,
		VerbResize,
		VerbHold,
		VerbSuspend,
		VerbDeprovision,
	}

	allResourceStates = []ResourceState{
		StatePending,
		StateProvisioning,
		StateReady,
		StateDegraded,
		StateSuspended,
		StateDeprovisioning,
		StateDeleted,
		StateFailed,
		StateDenied,
		StateBlocked,
		StateRetryable,
	}

	allHealthStatuses = []HealthStatus{
		HealthReady,
		HealthDegraded,
		HealthUnavailable,
	}
)

// AllServiceCategories returns a copy of the 9 canonical CloudRING service categories.
func AllServiceCategories() []ServiceCategory {
	out := make([]ServiceCategory, len(allServiceCategories))
	copy(out, allServiceCategories)
	return out
}

// ValidServiceCategory reports whether category is one of the 9 canonical OCS v3 categories.
func ValidServiceCategory(category ServiceCategory) bool {
	return slices.Contains(allServiceCategories, category)
}

// ValidBackendFamily reports whether family is a supported infrastructure substrate family.
func ValidBackendFamily(family BackendFamily) bool {
	return slices.Contains(allBackendFamilies, family)
}

// ValidLifecycleVerb reports whether verb is a supported OCS v3 lifecycle verb.
func ValidLifecycleVerb(verb LifecycleVerb) bool {
	return slices.Contains(allLifecycleVerbs, verb)
}

// ValidResourceState reports whether state is a canonical OCS v3 resource state.
func ValidResourceState(state ResourceState) bool {
	return slices.Contains(allResourceStates, state)
}

// ValidHealthStatus reports whether status is a canonical adapter health status.
func ValidHealthStatus(status HealthStatus) bool {
	return slices.Contains(allHealthStatuses, status)
}

// Parameter is a deterministic key/value attribute on a ProvisionRequest.
type Parameter struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ProvisionRequest describes a provider-neutral lifecycle request across the hexagonal seam.
type ProvisionRequest struct {
	SchemaVersion   string          `json:"schemaVersion"`
	ServiceCategory ServiceCategory `json:"serviceCategory"`
	AdapterID       string          `json:"adapterId"`
	TenantID        string          `json:"tenantId"`
	ProjectID       string          `json:"projectId"`
	ResourceID      string          `json:"resourceId"`
	IdempotencyKey  string          `json:"idempotencyKey"`
	Verb            LifecycleVerb   `json:"verb"`
	Parameters      []Parameter     `json:"parameters,omitempty"`
}

// ProvisionReceipt is the deterministic, source-safe receipt returned by a provider port.
type ProvisionReceipt struct {
	SchemaVersion    string          `json:"schemaVersion"`
	RequestSHA256    string          `json:"requestSha256"`
	CommitmentSHA256 string          `json:"commitmentSha256"`
	OperationID      string          `json:"operationId"`
	ProviderHandle   string          `json:"providerHandle"`
	AdapterID        string          `json:"adapterId"`
	ServiceCategory  ServiceCategory `json:"serviceCategory"`
	TenantID         string          `json:"tenantId"`
	ProjectID        string          `json:"projectId"`
	ResourceID       string          `json:"resourceId"`
	State            ResourceState   `json:"state"`
	BlockerCode      string          `json:"blockerCode,omitempty"`
}

// HealthReport describes the health of a registered provider adapter.
type HealthReport struct {
	AdapterID       string          `json:"adapterId"`
	ServiceCategory ServiceCategory `json:"serviceCategory"`
	BackendFamily   BackendFamily   `json:"backendFamily"`
	Status          HealthStatus    `json:"status"`
	Reason          string          `json:"reason,omitempty"`
}

// ValidateHealthReport checks that a HealthReport carries canonical fields.
func ValidateHealthReport(report HealthReport) error {
	if !validIdentifier(report.AdapterID) ||
		!ValidServiceCategory(report.ServiceCategory) ||
		!ValidBackendFamily(report.BackendFamily) ||
		!ValidHealthStatus(report.Status) ||
		(report.Status != HealthReady && strings.TrimSpace(report.Reason) == "") {
		return ErrInvalidHealthStatus
	}
	return nil
}

// NewProvisionRequest canonicalizes parameters and validates the resulting ProvisionRequest.
func NewProvisionRequest(
	category ServiceCategory,
	adapterID, tenantID, projectID, resourceID, idempotencyKey string,
	verb LifecycleVerb,
	params map[string]string,
) (ProvisionRequest, error) {
	sortedParams := make([]Parameter, 0, len(params))
	for k, v := range params {
		sortedParams = append(sortedParams, Parameter{Key: k, Value: v})
	}
	sort.Slice(sortedParams, func(i, j int) bool {
		return sortedParams[i].Key < sortedParams[j].Key
	})
	req := ProvisionRequest{
		SchemaVersion:   ProvisionRequestSchemaVersion,
		ServiceCategory: category,
		AdapterID:       adapterID,
		TenantID:        tenantID,
		ProjectID:       projectID,
		ResourceID:      resourceID,
		IdempotencyKey:  idempotencyKey,
		Verb:            verb,
		Parameters:      sortedParams,
	}
	if err := ValidateProvisionRequest(req); err != nil {
		return ProvisionRequest{}, err
	}
	return req, nil
}

// ValidateProvisionRequest enforces strict structural and ordering invariants on a ProvisionRequest.
func ValidateProvisionRequest(req ProvisionRequest) error {
	if req.SchemaVersion != ProvisionRequestSchemaVersion ||
		!ValidServiceCategory(req.ServiceCategory) ||
		!validIdentifier(req.AdapterID) ||
		!validIdentifier(req.TenantID) ||
		!validIdentifier(req.ProjectID) ||
		!validIdentifier(req.ResourceID) ||
		!validIdentifier(req.IdempotencyKey) ||
		!ValidLifecycleVerb(req.Verb) ||
		len(req.Parameters) > MaxParametersCount {
		return ErrInvalidRequest
	}
	for i, param := range req.Parameters {
		if !paramKeyPattern.MatchString(param.Key) ||
			strings.TrimSpace(param.Value) == "" ||
			len(param.Value) > MaxParameterValue ||
			strings.ContainsRune(param.Value, 0) {
			return ErrInvalidRequest
		}
		if i > 0 && req.Parameters[i-1].Key >= param.Key {
			return ErrInvalidRequest
		}
	}
	return nil
}

// RequestSHA256 computes the canonical domain-separated SHA-256 digest of a validated ProvisionRequest.
func RequestSHA256(req ProvisionRequest) (string, error) {
	if err := ValidateProvisionRequest(req); err != nil {
		return "", err
	}
	hash := sha256.New()
	writeField := func(value string) {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	writeField(req.SchemaVersion)
	writeField(string(req.ServiceCategory))
	writeField(req.AdapterID)
	writeField(req.TenantID)
	writeField(req.ProjectID)
	writeField(req.ResourceID)
	writeField(req.IdempotencyKey)
	writeField(string(req.Verb))
	for _, p := range req.Parameters {
		writeField(p.Key)
		writeField(p.Value)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// ReceiptCommitmentSHA256 computes the deterministic SHA-256 commitment binding
// a validated request, resulting resource state, and provider handle.
func ReceiptCommitmentSHA256(req ProvisionRequest, state ResourceState, providerHandle string) (string, error) {
	reqDigest, err := RequestSHA256(req)
	if err != nil {
		return "", err
	}
	if !ValidResourceState(state) || !validIdentifier(providerHandle) {
		return "", ErrInvalidReceipt
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(commitmentDomainPrefix))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(reqDigest))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(state))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(providerHandle))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// NewProvisionReceipt builds and validates a deterministic ProvisionReceipt for a request.
func NewProvisionReceipt(
	req ProvisionRequest,
	operationID string,
	state ResourceState,
	providerHandle string,
	blockerCode string,
) (ProvisionReceipt, error) {
	reqDigest, err := RequestSHA256(req)
	if err != nil {
		return ProvisionReceipt{}, ErrInvalidReceipt
	}
	commitment, err := ReceiptCommitmentSHA256(req, state, providerHandle)
	if err != nil {
		return ProvisionReceipt{}, ErrInvalidReceipt
	}
	receipt := ProvisionReceipt{
		SchemaVersion:    ProvisionReceiptSchemaVersion,
		RequestSHA256:    reqDigest,
		CommitmentSHA256: commitment,
		OperationID:      operationID,
		ProviderHandle:   providerHandle,
		AdapterID:        req.AdapterID,
		ServiceCategory:  req.ServiceCategory,
		TenantID:         req.TenantID,
		ProjectID:        req.ProjectID,
		ResourceID:       req.ResourceID,
		State:            state,
		BlockerCode:      blockerCode,
	}
	if err := ValidateProvisionReceipt(req, receipt); err != nil {
		return ProvisionReceipt{}, err
	}
	return receipt, nil
}

// ValidateProvisionReceipt verifies that receipt matches request, recomputes the
// cryptographic commitment from (req, state, providerHandle), and enforces state invariants.
func ValidateProvisionReceipt(req ProvisionRequest, receipt ProvisionReceipt) error {
	reqDigest, err := RequestSHA256(req)
	if err != nil {
		return ErrInvalidReceipt
	}
	expectedCommitment, err := ReceiptCommitmentSHA256(req, receipt.State, receipt.ProviderHandle)
	if err != nil {
		return ErrInvalidReceipt
	}
	if receipt.SchemaVersion != ProvisionReceiptSchemaVersion ||
		receipt.RequestSHA256 != reqDigest ||
		!digestPattern.MatchString(receipt.CommitmentSHA256) ||
		receipt.CommitmentSHA256 != expectedCommitment ||
		!validIdentifier(receipt.OperationID) ||
		receipt.AdapterID != req.AdapterID ||
		receipt.ServiceCategory != req.ServiceCategory ||
		receipt.TenantID != req.TenantID ||
		receipt.ProjectID != req.ProjectID ||
		receipt.ResourceID != req.ResourceID {
		return ErrInvalidReceipt
	}
	requiresBlocker := receipt.State == StateBlocked || receipt.State == StateDenied || receipt.State == StateFailed || receipt.State == StateRetryable
	if requiresBlocker && !validIdentifier(receipt.BlockerCode) {
		return ErrInvalidReceipt
	}
	if !requiresBlocker && receipt.BlockerCode != "" {
		return ErrInvalidReceipt
	}
	return nil
}

// ProviderPort is the common base hexagonal interface implemented by every category provider adapter.
type ProviderPort interface {
	AdapterID() string
	ServiceCategory() ServiceCategory
	BackendFamily() BackendFamily
	ExecuteLifecycle(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error)
	InspectResource(ctx context.Context, tenantID, projectID, resourceID string) (ProvisionReceipt, error)
	Health(ctx context.Context) (HealthReport, error)
}

// ComputeProvider is the hexagonal port for Compute (virtual machines & bare-metal instances).
type ComputeProvider interface {
	ProviderPort
	ProvisionInstance(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error)
}

// VolumeProvider is the hexagonal port for Block & File Storage volumes.
type VolumeProvider interface {
	ProviderPort
	ProvisionVolume(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error)
}

// NetworkProvider is the hexagonal port for VPCs, subnets, security groups, and load balancers.
type NetworkProvider interface {
	ProviderPort
	ProvisionNetwork(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error)
}

// KubernetesClusterProvider is the hexagonal port for Managed Kubernetes clusters.
type KubernetesClusterProvider interface {
	ProviderPort
	ProvisionCluster(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error)
}

// ObjectStorageProvider is the hexagonal port for S3-compatible object storage buckets and policies.
type ObjectStorageProvider interface {
	ProviderPort
	ProvisionBucket(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error)
}

// BackupProvider is the hexagonal port for snapshot, backup vault, and disaster recovery policies.
type BackupProvider interface {
	ProviderPort
	ProvisionBackupPlan(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error)
}

// AccessControlProvider is the hexagonal port for IAM policies, workload identities, and zero-trust access.
type AccessControlProvider interface {
	ProviderPort
	ProvisionAccessPolicy(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error)
}

// SupportProvider is the hexagonal port for support plans, diagnostics routing, and SLA bindings.
type SupportProvider interface {
	ProviderPort
	ProvisionSupportSubscription(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error)
}

// ExternalIntegrationProvider is the hexagonal port for federated/third-party service connectors.
type ExternalIntegrationProvider interface {
	ProviderPort
	ProvisionExternalConnector(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error)
}

// AdapterDescriptor describes a registered adapter in deterministic listings.
type AdapterDescriptor struct {
	AdapterID       string          `json:"adapterId"`
	ServiceCategory ServiceCategory `json:"serviceCategory"`
	BackendFamily   BackendFamily   `json:"backendFamily"`
}

// ProviderRegistry manages registration and deterministic lookup of hexagonal provider adapters.
type ProviderRegistry struct {
	adapters map[string]ProviderPort
}

// NewProviderRegistry creates an empty ProviderRegistry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		adapters: make(map[string]ProviderPort),
	}
}

func registryKey(category ServiceCategory, adapterID string) string {
	return string(category) + "\x00" + adapterID
}

// Register adds a ProviderPort to the registry after validating its identity and category.
func (r *ProviderRegistry) Register(port ProviderPort) error {
	if port == nil ||
		!validIdentifier(port.AdapterID()) ||
		!ValidServiceCategory(port.ServiceCategory()) ||
		!ValidBackendFamily(port.BackendFamily()) {
		return ErrInvalidAdapterDescriptor
	}
	key := registryKey(port.ServiceCategory(), port.AdapterID())
	if _, exists := r.adapters[key]; exists {
		return ErrAdapterAlreadyRegistered
	}
	r.adapters[key] = port
	return nil
}

// Lookup retrieves a registered ProviderPort by ServiceCategory and AdapterID.
func (r *ProviderRegistry) Lookup(category ServiceCategory, adapterID string) (ProviderPort, error) {
	if !ValidServiceCategory(category) || !validIdentifier(adapterID) {
		return nil, ErrInvalidAdapterDescriptor
	}
	port, exists := r.adapters[registryKey(category, adapterID)]
	if !exists {
		return nil, ErrAdapterNotFound
	}
	return port, nil
}

// List returns all registered adapters in canonical (ServiceCategory, AdapterID) order.
func (r *ProviderRegistry) List() []AdapterDescriptor {
	descriptors := make([]AdapterDescriptor, 0, len(r.adapters))
	for _, port := range r.adapters {
		descriptors = append(descriptors, AdapterDescriptor{
			AdapterID:       port.AdapterID(),
			ServiceCategory: port.ServiceCategory(),
			BackendFamily:   port.BackendFamily(),
		})
	}
	sort.Slice(descriptors, func(i, j int) bool {
		if descriptors[i].ServiceCategory != descriptors[j].ServiceCategory {
			return descriptors[i].ServiceCategory < descriptors[j].ServiceCategory
		}
		return descriptors[i].AdapterID < descriptors[j].AdapterID
	})
	return descriptors
}

// InMemoryAdapter is a deterministic, thread-safe (single-goroutine contract) reference adapter
// implementing all 9 CloudRING provider port interfaces for contract & conformance verification.
type InMemoryAdapter struct {
	adapterID       string
	serviceCategory ServiceCategory
	backendFamily   BackendFamily
	healthStatus    HealthStatus
	healthReason    string
	idempotencyLog  map[string]idempotencyEntry
	resources       map[string]storedResource
}

type idempotencyEntry struct {
	requestSHA256 string
	receipt       ProvisionReceipt
}

type storedResource struct {
	tenantID  string
	projectID string
	receipt   ProvisionReceipt
}

// NewInMemoryAdapter constructs a validated InMemoryAdapter for the given category and backend family.
func NewInMemoryAdapter(adapterID string, category ServiceCategory, family BackendFamily) (*InMemoryAdapter, error) {
	if !validIdentifier(adapterID) || !ValidServiceCategory(category) || !ValidBackendFamily(family) {
		return nil, ErrInvalidAdapterDescriptor
	}
	return &InMemoryAdapter{
		adapterID:       adapterID,
		serviceCategory: category,
		backendFamily:   family,
		healthStatus:    HealthReady,
		idempotencyLog:  make(map[string]idempotencyEntry),
		resources:       make(map[string]storedResource),
	}, nil
}

func (a *InMemoryAdapter) AdapterID() string                { return a.adapterID }
func (a *InMemoryAdapter) ServiceCategory() ServiceCategory { return a.serviceCategory }
func (a *InMemoryAdapter) BackendFamily() BackendFamily     { return a.backendFamily }

// SetHealth updates the adapter's reported health status and reason.
func (a *InMemoryAdapter) SetHealth(status HealthStatus, reason string) error {
	report := HealthReport{
		AdapterID:       a.adapterID,
		ServiceCategory: a.serviceCategory,
		BackendFamily:   a.backendFamily,
		Status:          status,
		Reason:          reason,
	}
	if err := ValidateHealthReport(report); err != nil {
		return err
	}
	a.healthStatus = status
	a.healthReason = reason
	return nil
}

// Health returns the adapter's current HealthReport, respecting context cancellation.
func (a *InMemoryAdapter) Health(ctx context.Context) (HealthReport, error) {
	if err := checkContext(ctx); err != nil {
		return HealthReport{}, err
	}
	return HealthReport{
		AdapterID:       a.adapterID,
		ServiceCategory: a.serviceCategory,
		BackendFamily:   a.backendFamily,
		Status:          a.healthStatus,
		Reason:          a.healthReason,
	}, nil
}

// ExecuteLifecycle executes a canonical lifecycle operation with strict tenant isolation and idempotency.
func (a *InMemoryAdapter) ExecuteLifecycle(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error) {
	if err := checkContext(ctx); err != nil {
		return ProvisionReceipt{}, err
	}
	if err := ValidateProvisionRequest(req); err != nil {
		return ProvisionReceipt{}, err
	}
	if req.AdapterID != a.adapterID || req.ServiceCategory != a.serviceCategory {
		return ProvisionReceipt{}, ErrInvalidRequest
	}
	reqDigest, _ := RequestSHA256(req)

	if existing, exists := a.resources[req.ResourceID]; exists {
		if existing.tenantID != req.TenantID || existing.projectID != req.ProjectID {
			return ProvisionReceipt{}, ErrTenantIsolationViolation
		}
	} else if req.Verb != VerbProvision {
		return ProvisionReceipt{}, ErrResourceNotFound
	}

	idemKey := req.TenantID + "\x00" + req.ProjectID + "\x00" + req.ResourceID + "\x00" + req.IdempotencyKey
	if prior, seen := a.idempotencyLog[idemKey]; seen {
		if prior.requestSHA256 != reqDigest {
			return ProvisionReceipt{}, ErrIdempotencyConflict
		}
		return prior.receipt, nil
	}

	targetState := stateForVerb(req.Verb)
	opID := "op-" + reqDigest[:24]
	handleSum := sha256.Sum256([]byte(string(a.backendFamily) + "\x00" + req.TenantID + "\x00" + req.ProjectID + "\x00" + req.ResourceID))
	handle := fmt.Sprintf("hdl-%s-%s", a.backendFamily, hex.EncodeToString(handleSum[:10]))
	receipt, _ := NewProvisionReceipt(req, opID, targetState, handle, "")
	a.idempotencyLog[idemKey] = idempotencyEntry{
		requestSHA256: reqDigest,
		receipt:       receipt,
	}
	a.resources[req.ResourceID] = storedResource{
		tenantID:  req.TenantID,
		projectID: req.ProjectID,
		receipt:   receipt,
	}
	return receipt, nil
}

// InspectResource returns the latest receipt for a resource if and only if tenantID and projectID match.
func (a *InMemoryAdapter) InspectResource(ctx context.Context, tenantID, projectID, resourceID string) (ProvisionReceipt, error) {
	if err := checkContext(ctx); err != nil {
		return ProvisionReceipt{}, err
	}
	if !validIdentifier(tenantID) || !validIdentifier(projectID) || !validIdentifier(resourceID) {
		return ProvisionReceipt{}, ErrInvalidRequest
	}
	stored, exists := a.resources[resourceID]
	if !exists {
		return ProvisionReceipt{}, ErrResourceNotFound
	}
	if stored.tenantID != tenantID || stored.projectID != projectID {
		return ProvisionReceipt{}, ErrTenantIsolationViolation
	}
	return stored.receipt, nil
}

func (a *InMemoryAdapter) ProvisionInstance(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error) {
	return a.ExecuteLifecycle(ctx, req)
}

func (a *InMemoryAdapter) ProvisionVolume(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error) {
	return a.ExecuteLifecycle(ctx, req)
}

func (a *InMemoryAdapter) ProvisionNetwork(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error) {
	return a.ExecuteLifecycle(ctx, req)
}

func (a *InMemoryAdapter) ProvisionCluster(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error) {
	return a.ExecuteLifecycle(ctx, req)
}

func (a *InMemoryAdapter) ProvisionBucket(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error) {
	return a.ExecuteLifecycle(ctx, req)
}

func (a *InMemoryAdapter) ProvisionBackupPlan(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error) {
	return a.ExecuteLifecycle(ctx, req)
}

func (a *InMemoryAdapter) ProvisionAccessPolicy(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error) {
	return a.ExecuteLifecycle(ctx, req)
}

func (a *InMemoryAdapter) ProvisionSupportSubscription(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error) {
	return a.ExecuteLifecycle(ctx, req)
}

func (a *InMemoryAdapter) ProvisionExternalConnector(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error) {
	return a.ExecuteLifecycle(ctx, req)
}

// ConformanceResult summarizes the contract verification of a ProviderPort implementation.
type ConformanceResult struct {
	AdapterID       string          `json:"adapterId"`
	ServiceCategory ServiceCategory `json:"serviceCategory"`
	BackendFamily   BackendFamily   `json:"backendFamily"`
	Passed          bool            `json:"passed"`
	VerifiedChecks  []string        `json:"verifiedChecks"`
}

// RunConformanceSuite executes the hexagonal contract test harness against port,
// verifying health reporting, idempotency, conflict detection, context cancellation,
// tenant/project isolation, and lifecycle transitions.
func RunConformanceSuite(port ProviderPort) (ConformanceResult, error) {
	if port == nil {
		return ConformanceResult{}, ErrInvalidAdapterDescriptor
	}
	ctx := context.Background()
	health, err := port.Health(ctx)
	if err != nil {
		return ConformanceResult{}, err
	}
	if err := ValidateHealthReport(health); err != nil {
		return ConformanceResult{}, err
	}

	req, err := NewProvisionRequest(
		port.ServiceCategory(),
		port.AdapterID(),
		"tenant-alpha",
		"project-core",
		"res-conformance-01",
		"idem-create-01",
		VerbProvision,
		map[string]string{"profile": "standard-v1"},
	)
	if err != nil {
		return ConformanceResult{}, err
	}

	firstReceipt, err := port.ExecuteLifecycle(ctx, req)
	if err != nil {
		return ConformanceResult{}, err
	}
	if err := ValidateProvisionReceipt(req, firstReceipt); err != nil || firstReceipt.State != StateReady {
		return ConformanceResult{}, ErrInvalidReceipt
	}

	replayReceipt, err := port.ExecuteLifecycle(ctx, req)
	if err != nil {
		return ConformanceResult{}, err
	}
	if replayReceipt != firstReceipt {
		return ConformanceResult{}, ErrIdempotencyConflict
	}

	conflictingReq, _ := NewProvisionRequest(
		port.ServiceCategory(),
		port.AdapterID(),
		"tenant-alpha",
		"project-core",
		"res-conformance-01",
		"idem-create-01",
		VerbProvision,
		map[string]string{"profile": "mutated-v2"},
	)
	if _, err := port.ExecuteLifecycle(ctx, conflictingReq); !errors.Is(err, ErrIdempotencyConflict) {
		return ConformanceResult{}, ErrIdempotencyConflict
	}

	if _, err := port.InspectResource(ctx, "tenant-bravo", "project-core", "res-conformance-01"); !errors.Is(err, ErrTenantIsolationViolation) {
		return ConformanceResult{}, ErrTenantIsolationViolation
	}

	crossTenantMutate, _ := NewProvisionRequest(
		port.ServiceCategory(),
		port.AdapterID(),
		"tenant-bravo",
		"project-core",
		"res-conformance-01",
		"idem-bravo-01",
		VerbDeprovision,
		nil,
	)
	if _, err := port.ExecuteLifecycle(ctx, crossTenantMutate); !errors.Is(err, ErrTenantIsolationViolation) {
		return ConformanceResult{}, ErrTenantIsolationViolation
	}

	transitions := []struct {
		idemKey       string
		verb          LifecycleVerb
		expectedState ResourceState
	}{
		{idemKey: "idem-resize-01", verb: VerbResize, expectedState: StateReady},
		{idemKey: "idem-hold-01", verb: VerbHold, expectedState: StateSuspended},
		{idemKey: "idem-resume-01", verb: VerbResume, expectedState: StateReady},
		{idemKey: "idem-suspend-01", verb: VerbSuspend, expectedState: StateSuspended},
		{idemKey: "idem-deprov-01", verb: VerbDeprovision, expectedState: StateDeleted},
	}
	for _, step := range transitions {
		stepReq, _ := NewProvisionRequest(
			port.ServiceCategory(),
			port.AdapterID(),
			"tenant-alpha",
			"project-core",
			"res-conformance-01",
			step.idemKey,
			step.verb,
			nil,
		)
		stepReceipt, err := port.ExecuteLifecycle(ctx, stepReq)
		if err != nil {
			return ConformanceResult{}, err
		}
		if err := ValidateProvisionReceipt(stepReq, stepReceipt); err != nil || stepReceipt.State != step.expectedState {
			return ConformanceResult{}, ErrInvalidReceipt
		}
	}

	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := port.ExecuteLifecycle(canceledCtx, req); !errors.Is(err, ErrContextCanceled) {
		return ConformanceResult{}, ErrContextCanceled
	}

	return ConformanceResult{
		AdapterID:       port.AdapterID(),
		ServiceCategory: port.ServiceCategory(),
		BackendFamily:   port.BackendFamily(),
		Passed:          true,
		VerifiedChecks: []string{
			"health_report_schema",
			"provision_receipt_commitment",
			"idempotent_replay_determinism",
			"idempotency_conflict_rejection",
			"tenant_and_project_isolation",
			"lifecycle_state_transitions",
			"context_cancellation_propagation",
		},
	}, nil
}

func stateForVerb(verb LifecycleVerb) ResourceState {
	switch verb {
	case VerbHold, VerbSuspend:
		return StateSuspended
	case VerbDeprovision:
		return StateDeleted
	default:
		return StateReady
	}
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return ErrContextCanceled
	}
	if err := ctx.Err(); err != nil {
		return ErrContextCanceled
	}
	return nil
}

func validIdentifier(value string) bool {
	return identifierPattern.MatchString(value) && !strings.Contains(value, "..")
}
