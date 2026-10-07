// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Package provideradapter defines provider-neutral protocols between
// CloudRING core and downstream infrastructure adapters.
package provideradapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const (
	InventoryRequestSchemaVersion = "cloudring.provider-adapter.inventory-request/v1"
	InventoryReceiptSchemaVersion = "cloudring.provider-adapter.inventory-receipt/v1"
	InventoryScope                = "provider-inventory"
	MaxInventoryDocumentBytes     = 1 << 20
	MaxInventoryBindings          = 4096
	ObservationNonceBytes         = 32
	maxCanonicalObservationBytes  = 1 << 20
	observationCommitmentDomain   = "cloudring/provider-inventory/observation/v1"

	BindingProviderAdapterReference     BindingClass = "provider-adapter-reference"
	BindingRegionInventoryReference     BindingClass = "region-inventory-reference"
	BindingProviderResourceReference    BindingClass = "provider-resource-reference"
	BindingManagementAddressReference   BindingClass = "management-address-reference"
	BindingProvisioningAddressReference BindingClass = "provisioning-address-reference"

	StatusReady     InventoryStatus = "ready"
	StatusBlocked   InventoryStatus = "blocked"
	StatusDenied    InventoryStatus = "denied"
	StatusRetryable InventoryStatus = "retryable"
	StatusFailed    InventoryStatus = "failed"
)

var (
	ErrInvalidInventoryRequest = errors.New("invalid provider inventory request")
	ErrInvalidInventoryReceipt = errors.New("invalid provider inventory receipt")
	ErrInvalidObservation      = errors.New("invalid provider inventory observation")
	digestPattern              = regexp.MustCompile(`^[a-f0-9]{64}$`)
	referencePattern           = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._/-][a-z0-9]+)*$`)
	blockerPattern             = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
	bindingClassOrder          = []BindingClass{
		BindingProviderAdapterReference,
		BindingRegionInventoryReference,
		BindingProviderResourceReference,
		BindingManagementAddressReference,
		BindingProvisioningAddressReference,
	}
	inventoryStatuses = []InventoryStatus{
		StatusReady,
		StatusBlocked,
		StatusDenied,
		StatusRetryable,
		StatusFailed,
	}
)

type BindingClass string

type InventoryStatus string

// InventoryBinding is a source-safe symbolic lookup. A downstream adapter
// resolves Reference privately; the request never carries the resolved value.
type InventoryBinding struct {
	BindingClass BindingClass `json:"bindingClass"`
	Reference    string       `json:"reference"`
}

// InventoryRequest asks a downstream adapter to discover an exact, bounded
// set of symbolic bindings. Digest fields bind private runtime state without
// putting that state into the public protocol.
type InventoryRequest struct {
	SchemaVersion        string             `json:"schemaVersion"`
	Scope                string             `json:"scope"`
	ProfileSHA256        string             `json:"profileSha256"`
	RunNonceSHA256       string             `json:"runNonceSha256"`
	AdapterCatalogSHA256 string             `json:"adapterCatalogSha256"`
	Bindings             []InventoryBinding `json:"bindings"`
	ProductionReady      bool               `json:"productionReady"`
}

// InventoryObservation commits to the private value observed for one exact
// request binding. The value itself must remain downstream.
type InventoryObservation struct {
	BindingClass                BindingClass `json:"bindingClass"`
	Reference                   string       `json:"reference"`
	ObservationCommitmentSHA256 string       `json:"observationCommitmentSha256"`
}

// InventoryReceipt is intentionally not a production-readiness assertion.
// A ready status means only that every requested symbolic binding was
// observed and committed to by the adapter.
type InventoryReceipt struct {
	SchemaVersion           string                 `json:"schemaVersion"`
	Scope                   string                 `json:"scope"`
	Status                  InventoryStatus        `json:"status"`
	RequestSHA256           string                 `json:"requestSha256"`
	AdapterExecutableSHA256 string                 `json:"adapterExecutableSha256"`
	AdapterCatalogSHA256    string                 `json:"adapterCatalogSha256"`
	Observations            []InventoryObservation `json:"observations"`
	BlockerIDs              []string               `json:"blockerIds"`
	ProductionReady         bool                   `json:"productionReady"`
}

// NewInventoryRequest returns the canonical request ordering used for hashing,
// signing, replay comparison, and exact receipt matching.
func NewInventoryRequest(profileSHA256, runNonceSHA256, adapterCatalogSHA256 string, bindings []InventoryBinding) (InventoryRequest, error) {
	request := InventoryRequest{
		SchemaVersion:        InventoryRequestSchemaVersion,
		Scope:                InventoryScope,
		ProfileSHA256:        profileSHA256,
		RunNonceSHA256:       runNonceSHA256,
		AdapterCatalogSHA256: adapterCatalogSHA256,
		Bindings:             append([]InventoryBinding(nil), bindings...),
		ProductionReady:      false,
	}
	sort.Slice(request.Bindings, func(left, right int) bool {
		leftRank := bindingRank(request.Bindings[left].BindingClass)
		rightRank := bindingRank(request.Bindings[right].BindingClass)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		return request.Bindings[left].Reference < request.Bindings[right].Reference
	})
	if err := ValidateInventoryRequest(request); err != nil {
		return InventoryRequest{}, err
	}
	return request, nil
}

func ValidateInventoryRequest(request InventoryRequest) error {
	if request.SchemaVersion != InventoryRequestSchemaVersion ||
		request.Scope != InventoryScope ||
		!validDigest(request.ProfileSHA256) ||
		!validDigest(request.RunNonceSHA256) ||
		!validDigest(request.AdapterCatalogSHA256) ||
		request.ProductionReady ||
		len(request.Bindings) == 0 ||
		len(request.Bindings) > MaxInventoryBindings {
		return ErrInvalidInventoryRequest
	}
	seen := make(map[string]struct{}, len(request.Bindings))
	seenReferences := make(map[string]struct{}, len(request.Bindings))
	for index, binding := range request.Bindings {
		if !validBinding(binding) {
			return ErrInvalidInventoryRequest
		}
		key := string(binding.BindingClass) + "\x00" + binding.Reference
		if _, exists := seen[key]; exists {
			return ErrInvalidInventoryRequest
		}
		if _, exists := seenReferences[binding.Reference]; exists {
			return ErrInvalidInventoryRequest
		}
		seen[key] = struct{}{}
		seenReferences[binding.Reference] = struct{}{}
		if index > 0 && !bindingLess(request.Bindings[index-1], binding) {
			return ErrInvalidInventoryRequest
		}
	}
	return nil
}

func DecodeInventoryRequest(reader io.Reader) (InventoryRequest, error) {
	payload, err := readInventoryDocument(reader)
	if err != nil {
		return InventoryRequest{}, ErrInvalidInventoryRequest
	}
	var request InventoryRequest
	if strictjson.DecodeExact(payload, &request) != nil || ValidateInventoryRequest(request) != nil {
		return InventoryRequest{}, ErrInvalidInventoryRequest
	}
	return request, nil
}

// InventoryRequestSHA256 is the canonical request commitment echoed by every
// receipt. Valid requests use structs and ordered slices, so encoding is
// deterministic across calls.
func InventoryRequestSHA256(request InventoryRequest) (string, error) {
	if err := ValidateInventoryRequest(request); err != nil {
		return "", err
	}
	return sha256JSON(request), nil
}

// NewInventoryReceipt constructs a value-free receipt from a canonical ordered
// observation set. Ready receipts require every request binding; non-ready
// receipts may carry the exact ordered subset collected before the blocker.
func NewInventoryReceipt(request InventoryRequest, status InventoryStatus, adapterExecutableSHA256 string, observations []InventoryObservation, blockerIDs []string) (InventoryReceipt, error) {
	requestSHA256, err := InventoryRequestSHA256(request)
	if err != nil {
		return InventoryReceipt{}, ErrInvalidInventoryReceipt
	}
	receipt := InventoryReceipt{
		SchemaVersion:           InventoryReceiptSchemaVersion,
		Scope:                   InventoryScope,
		Status:                  status,
		RequestSHA256:           requestSHA256,
		AdapterExecutableSHA256: adapterExecutableSHA256,
		AdapterCatalogSHA256:    request.AdapterCatalogSHA256,
		Observations:            make([]InventoryObservation, len(observations)),
		BlockerIDs:              make([]string, len(blockerIDs)),
		ProductionReady:         false,
	}
	copy(receipt.Observations, observations)
	copy(receipt.BlockerIDs, blockerIDs)
	sort.Strings(receipt.BlockerIDs)
	if err := ValidateInventoryReceipt(request, receipt); err != nil {
		return InventoryReceipt{}, err
	}
	return receipt, nil
}

func ValidateInventoryReceipt(request InventoryRequest, receipt InventoryReceipt) error {
	requestSHA256, err := InventoryRequestSHA256(request)
	if err != nil ||
		receipt.SchemaVersion != InventoryReceiptSchemaVersion ||
		receipt.Scope != InventoryScope ||
		!slices.Contains(inventoryStatuses, receipt.Status) ||
		receipt.RequestSHA256 != requestSHA256 ||
		!validDigest(receipt.AdapterExecutableSHA256) ||
		receipt.AdapterCatalogSHA256 != request.AdapterCatalogSHA256 ||
		receipt.ProductionReady ||
		receipt.Observations == nil ||
		len(receipt.Observations) > len(request.Bindings) ||
		receipt.Status == StatusReady && len(receipt.Observations) != len(request.Bindings) ||
		receipt.BlockerIDs == nil ||
		!validBlockers(receipt.Status, receipt.BlockerIDs) {
		return ErrInvalidInventoryReceipt
	}
	nextRequestIndex := 0
	for _, observation := range receipt.Observations {
		if !validDigest(observation.ObservationCommitmentSHA256) {
			return ErrInvalidInventoryReceipt
		}
		matched := false
		for nextRequestIndex < len(request.Bindings) {
			expected := request.Bindings[nextRequestIndex]
			nextRequestIndex++
			if observation.BindingClass == expected.BindingClass && observation.Reference == expected.Reference {
				matched = true
				break
			}
		}
		if !matched {
			return ErrInvalidInventoryReceipt
		}
	}
	return nil
}

// RunNonceSHA256 returns the request-visible digest of an exact 256-bit
// protected per-run nonce.
func RunNonceSHA256(rawNonce []byte) (string, error) {
	if len(rawNonce) != ObservationNonceBytes {
		return "", ErrInvalidObservation
	}
	return sha256Bytes(rawNonce), nil
}

// ObservationCommitmentSHA256 creates the domain-separated salted commitment
// stored in a receipt. The raw nonce and canonical private value must be passed
// through protected runtime input and are never retained or returned.
func ObservationCommitmentSHA256(request InventoryRequest, rawNonce []byte, binding InventoryBinding, canonicalPrivateValue []byte) (string, error) {
	runNonceSHA256, nonceErr := RunNonceSHA256(rawNonce)
	if len(rawNonce) != ObservationNonceBytes ||
		nonceErr != nil ||
		ValidateInventoryRequest(request) != nil ||
		runNonceSHA256 != request.RunNonceSHA256 ||
		!slices.Contains(request.Bindings, binding) ||
		!validBinding(binding) ||
		len(canonicalPrivateValue) == 0 ||
		len(canonicalPrivateValue) > maxCanonicalObservationBytes {
		return "", ErrInvalidObservation
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(observationCommitmentDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(rawNonce)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(binding.Reference))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(canonicalPrivateValue)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func DecodeInventoryReceipt(reader io.Reader, request InventoryRequest) (InventoryReceipt, error) {
	payload, err := readInventoryDocument(reader)
	if err != nil {
		return InventoryReceipt{}, ErrInvalidInventoryReceipt
	}
	var receipt InventoryReceipt
	if strictjson.DecodeExact(payload, &receipt) != nil || ValidateInventoryReceipt(request, receipt) != nil {
		return InventoryReceipt{}, ErrInvalidInventoryReceipt
	}
	return receipt, nil
}

func validBinding(binding InventoryBinding) bool {
	return bindingRank(binding.BindingClass) >= 0 &&
		len(binding.Reference) >= 3 &&
		len(binding.Reference) <= 253 &&
		referencePattern.MatchString(binding.Reference) &&
		!strings.Contains(binding.Reference, "..") &&
		!strings.Contains(binding.Reference, "//")
}

func bindingLess(left, right InventoryBinding) bool {
	leftRank := bindingRank(left.BindingClass)
	rightRank := bindingRank(right.BindingClass)
	return leftRank < rightRank || leftRank == rightRank && left.Reference < right.Reference
}

func bindingRank(class BindingClass) int {
	return slices.Index(bindingClassOrder, class)
}

func validBlockers(status InventoryStatus, blockers []string) bool {
	if status == StatusReady {
		return len(blockers) == 0
	}
	if len(blockers) == 0 || len(blockers) > 32 {
		return false
	}
	for index, blocker := range blockers {
		if len(blocker) > 63 || !blockerPattern.MatchString(blocker) ||
			index > 0 && blockers[index-1] >= blocker {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	return digestPattern.MatchString(value)
}

func readInventoryDocument(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("missing provider inventory document")
	}
	payload, err := io.ReadAll(io.LimitReader(reader, MaxInventoryDocumentBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > MaxInventoryDocumentBytes {
		return nil, errors.New("invalid provider inventory document")
	}
	if strictjson.Validate(payload) != nil {
		return nil, errors.New("invalid provider inventory document")
	}
	return payload, nil
}

func sha256JSON(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func sha256Bytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
