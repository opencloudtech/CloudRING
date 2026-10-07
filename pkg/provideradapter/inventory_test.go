// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package provideradapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestInventoryRequestAndReceiptAreDeterministicAndValueFree(t *testing.T) {
	t.Parallel()
	bindings := syntheticThreeNodeBindings()
	slices.Reverse(bindings)
	runNonceSHA256, err := RunNonceSHA256(syntheticRunNonce())
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewInventoryRequest(testDigest("profile"), runNonceSHA256, testDigest("catalog"), bindings)
	if err != nil {
		t.Fatal(err)
	}
	again, err := NewInventoryRequest(testDigest("profile"), runNonceSHA256, testDigest("catalog"), bindings)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(again)
	if err != nil || !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("request is not deterministic: %v", err)
	}
	if len(request.Bindings) != 11 {
		t.Fatalf("three-node site request has %d bindings, want 11", len(request.Bindings))
	}
	assertClassCount(t, request.Bindings, BindingProviderAdapterReference, 1)
	assertClassCount(t, request.Bindings, BindingRegionInventoryReference, 1)
	assertClassCount(t, request.Bindings, BindingProviderResourceReference, 3)
	assertClassCount(t, request.Bindings, BindingManagementAddressReference, 3)
	assertClassCount(t, request.Bindings, BindingProvisioningAddressReference, 3)

	observations := syntheticObservations(t, request)
	receipt, err := NewInventoryReceipt(request, StatusReady, testDigest("adapter executable"), observations, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiptAgain, err := NewInventoryReceipt(request, StatusReady, testDigest("adapter executable"), observations, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiptJSON, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptAgainJSON, err := json.Marshal(receiptAgain)
	if err != nil || !bytes.Equal(receiptJSON, receiptAgainJSON) {
		t.Fatalf("receipt is not deterministic: %v", err)
	}
	if request.Scope != InventoryScope || receipt.Scope != InventoryScope || receipt.ProductionReady || request.ProductionReady {
		t.Fatal("inventory protocol made a production-readiness claim")
	}
	for _, forbidden := range []string{
		"192.0.2.10",
		"2001:db8::10",
		"provider-server-id",
		"network-id",
		"bearer-token",
		"observedValue",
		"responseBody",
		"canonical-synthetic-value",
	} {
		if bytes.Contains(firstJSON, []byte(forbidden)) || bytes.Contains(receiptJSON, []byte(forbidden)) {
			t.Fatalf("value-free inventory protocol leaked %q", forbidden)
		}
	}
	decodedRequest, err := DecodeInventoryRequest(bytes.NewReader(firstJSON))
	if err != nil || decodedRequest.ProfileSHA256 != request.ProfileSHA256 {
		t.Fatalf("DecodeInventoryRequest() = %#v, %v", decodedRequest, err)
	}
	decodedReceipt, err := DecodeInventoryReceipt(bytes.NewReader(receiptJSON), request)
	if err != nil || decodedReceipt.RequestSHA256 != receipt.RequestSHA256 {
		t.Fatalf("DecodeInventoryReceipt() = %#v, %v", decodedReceipt, err)
	}
}

func TestInventoryProtocolSupportsBoundedGenericBindingSets(t *testing.T) {
	t.Parallel()
	request, err := NewInventoryRequest(
		testDigest("profile"),
		testDigest("nonce"),
		testDigest("catalog"),
		[]InventoryBinding{{
			BindingClass: BindingProviderAdapterReference,
			Reference:    "adapters.synthetic",
		}},
	)
	if err != nil || len(request.Bindings) != 1 {
		t.Fatalf("generic request rejected: %#v, %v", request, err)
	}
	wrongScope := request
	wrongScope.Scope = "other-scope"
	if err := ValidateInventoryRequest(wrongScope); !errors.Is(err, ErrInvalidInventoryRequest) {
		t.Fatalf("wrong request scope error = %v", err)
	}
	tooMany := make([]InventoryBinding, MaxInventoryBindings+1)
	for index := range tooMany {
		tooMany[index] = InventoryBinding{
			BindingClass: BindingProviderResourceReference,
			Reference:    "inventory.nodes.node-" + base26(index),
		}
	}
	if _, err := NewInventoryRequest(testDigest("profile"), testDigest("nonce"), testDigest("catalog"), tooMany); !errors.Is(err, ErrInvalidInventoryRequest) {
		t.Fatalf("unbounded request error = %v", err)
	}
	for _, bindings := range [][]InventoryBinding{
		{
			{BindingClass: BindingProviderResourceReference, Reference: "inventory.nodes.node-a"},
			{BindingClass: BindingProviderResourceReference, Reference: "inventory.nodes.node-a"},
		},
		{
			{BindingClass: BindingProviderResourceReference, Reference: "inventory.nodes.node-a"},
			{BindingClass: BindingManagementAddressReference, Reference: "inventory.nodes.node-a"},
		},
	} {
		if _, err := NewInventoryRequest(testDigest("profile"), testDigest("nonce"), testDigest("catalog"), bindings); !errors.Is(err, ErrInvalidInventoryRequest) {
			t.Fatalf("duplicate symbolic reference error = %v", err)
		}
	}
}

func TestObservationCommitmentIsDomainSeparatedAndSalted(t *testing.T) {
	t.Parallel()
	binding := InventoryBinding{
		BindingClass: BindingManagementAddressReference,
		Reference:    "inventory.synthetic.addresses.node-a.management",
	}
	alternateBinding := binding
	alternateBinding.Reference = "inventory.synthetic.addresses.node-b.management"
	nonce := syntheticRunNonce()
	nonceSHA256, err := RunNonceSHA256(nonce)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewInventoryRequest(testDigest("profile"), nonceSHA256, testDigest("catalog"), []InventoryBinding{binding, alternateBinding})
	if err != nil {
		t.Fatal(err)
	}
	privateValue := []byte("canonical-private-value")
	commitment, err := ObservationCommitmentSHA256(request, nonce, binding, privateValue)
	if err != nil {
		t.Fatal(err)
	}
	directValueHash := sha256.Sum256(privateValue)
	if commitment == hex.EncodeToString(directValueHash[:]) {
		t.Fatal("observation used an unsalted direct value hash")
	}
	expectedInput := make([]byte, 0, len(observationCommitmentDomain)+len(nonce)+len(binding.Reference)+len(privateValue)+3)
	expectedInput = append(expectedInput, observationCommitmentDomain...)
	expectedInput = append(expectedInput, 0)
	expectedInput = append(expectedInput, nonce...)
	expectedInput = append(expectedInput, 0)
	expectedInput = append(expectedInput, binding.Reference...)
	expectedInput = append(expectedInput, 0)
	expectedInput = append(expectedInput, privateValue...)
	expected := sha256.Sum256(expectedInput)
	if commitment != hex.EncodeToString(expected[:]) {
		t.Fatal("observation commitment does not use the specified domain-separated envelope")
	}
	alternateNonce := append([]byte(nil), nonce...)
	alternateNonce[0]++
	alternateNonceSHA256, err := RunNonceSHA256(alternateNonce)
	if err != nil {
		t.Fatal(err)
	}
	alternateNonceRequest, err := NewInventoryRequest(testDigest("profile"), alternateNonceSHA256, testDigest("catalog"), []InventoryBinding{binding, alternateBinding})
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]struct {
		request InventoryRequest
		nonce   []byte
		binding InventoryBinding
		value   []byte
	}{
		"nonce":     {request: alternateNonceRequest, nonce: alternateNonce, binding: binding, value: privateValue},
		"reference": {request: request, nonce: nonce, binding: alternateBinding, value: privateValue},
		"value":     {request: request, nonce: nonce, binding: binding, value: []byte("other-canonical-private-value")},
	} {
		other, err := ObservationCommitmentSHA256(input.request, input.nonce, input.binding, input.value)
		if err != nil || other == commitment {
			t.Fatalf("%s did not change commitment: %v", name, err)
		}
	}
	if nonceSHA256 != sha256Bytes(nonce) {
		t.Fatalf("run nonce commitment mismatch: %q", nonceSHA256)
	}
	if _, err := ObservationCommitmentSHA256(request, nonce[:len(nonce)-1], binding, privateValue); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("short nonce error = %v", err)
	}
	if _, err := ObservationCommitmentSHA256(request, nonce, binding, nil); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("empty private value error = %v", err)
	}
	if _, err := ObservationCommitmentSHA256(request, alternateNonce, binding, privateValue); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("request-mismatched nonce error = %v", err)
	}
}

func TestInventoryReceiptStatusAndExactRequestBinding(t *testing.T) {
	t.Parallel()
	request := mustSyntheticRequest(t)
	observations := syntheticObservations(t, request)
	for _, status := range inventoryStatuses {
		status := status
		t.Run(string(status), func(t *testing.T) {
			t.Parallel()
			var blockers []string
			if status != StatusReady {
				blockers = []string{"provider_observation_incomplete"}
			}
			receipt, err := NewInventoryReceipt(request, status, testDigest("adapter executable"), observations, blockers)
			if err != nil || ValidateInventoryReceipt(request, receipt) != nil {
				t.Fatalf("valid status %q rejected: %#v, %v", status, receipt, err)
			}
		})
	}
	denied, err := NewInventoryReceipt(request, StatusDenied, testDigest("adapter executable"), nil, []string{"provider_access_denied"})
	if err != nil || len(denied.Observations) != 0 || ValidateInventoryReceipt(request, denied) != nil {
		t.Fatalf("denied receipt without observations rejected: %#v, %v", denied, err)
	}
	tests := []struct {
		name   string
		mutate func(*InventoryReceipt)
	}{
		{name: "production claim", mutate: func(receipt *InventoryReceipt) { receipt.ProductionReady = true }},
		{name: "wrong scope", mutate: func(receipt *InventoryReceipt) { receipt.Scope = "other-scope" }},
		{name: "unknown status", mutate: func(receipt *InventoryReceipt) { receipt.Status = "degraded" }},
		{name: "wrong request", mutate: func(receipt *InventoryReceipt) { receipt.RequestSHA256 = testDigest("other request") }},
		{name: "wrong catalog", mutate: func(receipt *InventoryReceipt) { receipt.AdapterCatalogSHA256 = testDigest("other catalog") }},
		{name: "missing observation", mutate: func(receipt *InventoryReceipt) {
			receipt.Observations = receipt.Observations[:len(receipt.Observations)-1]
		}},
		{name: "reordered observation", mutate: func(receipt *InventoryReceipt) {
			receipt.Observations[0], receipt.Observations[1] = receipt.Observations[1], receipt.Observations[0]
		}},
		{name: "raw observation", mutate: func(receipt *InventoryReceipt) {
			receipt.Observations[0].ObservationCommitmentSHA256 = "192.0.2.10"
		}},
		{name: "ready blocker", mutate: func(receipt *InventoryReceipt) { receipt.BlockerIDs = []string{"unexpected_blocker"} }},
		{name: "unsorted blockers", mutate: func(receipt *InventoryReceipt) {
			receipt.Status = StatusBlocked
			receipt.BlockerIDs = []string{"z_last", "a_first"}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			receipt, err := NewInventoryReceipt(request, StatusReady, testDigest("adapter executable"), observations, nil)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&receipt)
			if err := ValidateInventoryReceipt(request, receipt); !errors.Is(err, ErrInvalidInventoryReceipt) {
				t.Fatalf("unsafe receipt error = %v", err)
			}
		})
	}
	for _, blockers := range [][]string{
		nil,
		{"UPPERCASE"},
		{"duplicate", "duplicate"},
	} {
		if _, err := NewInventoryReceipt(request, StatusBlocked, testDigest("adapter executable"), observations, blockers); !errors.Is(err, ErrInvalidInventoryReceipt) {
			t.Fatalf("unsafe blockers %#v error = %v", blockers, err)
		}
	}
	validSubset := []InventoryObservation{observations[0], observations[2]}
	if _, err := NewInventoryReceipt(request, StatusRetryable, testDigest("adapter executable"), validSubset, []string{"provider_api_retry"}); err != nil {
		t.Fatalf("ordered non-ready subset rejected: %v", err)
	}
	subsetTests := []struct {
		name         string
		observations []InventoryObservation
	}{
		{name: "unknown", observations: []InventoryObservation{{
			BindingClass:                BindingProviderResourceReference,
			Reference:                   "inventory.synthetic.nodes.unknown",
			ObservationCommitmentSHA256: testDigest("unknown"),
		}}},
		{name: "reordered", observations: []InventoryObservation{observations[2], observations[0]}},
		{name: "duplicate", observations: []InventoryObservation{observations[0], observations[0]}},
	}
	for _, test := range subsetTests {
		if _, err := NewInventoryReceipt(request, StatusBlocked, testDigest("adapter executable"), test.observations, []string{"provider_observation_incomplete"}); !errors.Is(err, ErrInvalidInventoryReceipt) {
			t.Fatalf("unsafe %s subset error = %v", test.name, err)
		}
	}
}

func TestInventoryDecodersRejectUnknownDuplicateTrailingAndOversizedJSON(t *testing.T) {
	t.Parallel()
	request := mustSyntheticRequest(t)
	requestJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewInventoryReceipt(request, StatusReady, testDigest("adapter executable"), syntheticObservations(t, request), nil)
	if err != nil {
		t.Fatal(err)
	}
	receiptJSON, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	requestCases := [][]byte{
		bytes.Replace(requestJSON, []byte(`"schemaVersion":`), []byte(`"unknown":true,"schemaVersion":`), 1),
		bytes.Replace(requestJSON, []byte(`"profileSha256":`), []byte(`"profileSha256":"`+testDigest("duplicate")+`","profileSha256":`), 1),
		append(append([]byte(nil), requestJSON...), []byte(` {}`)...),
		bytes.Repeat([]byte{'x'}, MaxInventoryDocumentBytes+1),
	}
	for index, payload := range requestCases {
		if _, err := DecodeInventoryRequest(bytes.NewReader(payload)); !errors.Is(err, ErrInvalidInventoryRequest) {
			t.Fatalf("unsafe request %d error = %v", index, err)
		}
	}
	receiptCases := [][]byte{
		bytes.Replace(receiptJSON, []byte(`"status":`), []byte(`"observedValue":"private","status":`), 1),
		bytes.Replace(receiptJSON, []byte(`"requestSha256":`), []byte(`"requestSha256":"`+testDigest("duplicate")+`","requestSha256":`), 1),
		append(append([]byte(nil), receiptJSON...), []byte(` {}`)...),
		bytes.Repeat([]byte{'x'}, MaxInventoryDocumentBytes+1),
	}
	for index, payload := range receiptCases {
		if _, err := DecodeInventoryReceipt(bytes.NewReader(payload), request); !errors.Is(err, ErrInvalidInventoryReceipt) {
			t.Fatalf("unsafe receipt %d error = %v", index, err)
		}
	}
}

func TestInventoryRuntimeDocumentsMatchPublicSchemas(t *testing.T) {
	t.Parallel()
	request := mustSyntheticRequest(t)
	receipt, err := NewInventoryReceipt(request, StatusReady, testDigest("adapter executable"), syntheticObservations(t, request), nil)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := NewInventoryReceipt(request, StatusDenied, testDigest("adapter executable"), nil, []string{"provider_access_denied"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		path  string
		value any
	}{
		{name: "request", path: "../../contracts/provider-adapter/inventory-request.schema.json", value: request},
		{name: "ready receipt", path: "../../contracts/provider-adapter/inventory-receipt.schema.json", value: receipt},
		{name: "denied receipt without observations", path: "../../contracts/provider-adapter/inventory-receipt.schema.json", value: denied},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			schema, err := jsonschema.NewCompiler().Compile(test.path)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(instance); err != nil {
				t.Fatalf("runtime document does not match %s: %v", test.path, err)
			}
			schemaPayload, err := os.ReadFile(test.path) // #nosec G304 -- repository-owned closed test path.
			if err != nil || !json.Valid(schemaPayload) {
				t.Fatalf("schema is not strict JSON: %v", err)
			}
		})
	}
}

func mustSyntheticRequest(t *testing.T) InventoryRequest {
	t.Helper()
	runNonceSHA256, err := RunNonceSHA256(syntheticRunNonce())
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewInventoryRequest(testDigest("profile"), runNonceSHA256, testDigest("catalog"), syntheticThreeNodeBindings())
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func syntheticThreeNodeBindings() []InventoryBinding {
	return []InventoryBinding{
		{BindingClass: BindingProviderAdapterReference, Reference: "adapters.synthetic"},
		{BindingClass: BindingRegionInventoryReference, Reference: "inventory.synthetic.region"},
		{BindingClass: BindingProviderResourceReference, Reference: "inventory.synthetic.nodes.node-a"},
		{BindingClass: BindingProviderResourceReference, Reference: "inventory.synthetic.nodes.node-b"},
		{BindingClass: BindingProviderResourceReference, Reference: "inventory.synthetic.nodes.node-c"},
		{BindingClass: BindingManagementAddressReference, Reference: "inventory.synthetic.addresses.node-a.management"},
		{BindingClass: BindingManagementAddressReference, Reference: "inventory.synthetic.addresses.node-b.management"},
		{BindingClass: BindingManagementAddressReference, Reference: "inventory.synthetic.addresses.node-c.management"},
		{BindingClass: BindingProvisioningAddressReference, Reference: "inventory.synthetic.addresses.node-a.provisioning"},
		{BindingClass: BindingProvisioningAddressReference, Reference: "inventory.synthetic.addresses.node-b.provisioning"},
		{BindingClass: BindingProvisioningAddressReference, Reference: "inventory.synthetic.addresses.node-c.provisioning"},
	}
}

func syntheticObservations(t *testing.T, request InventoryRequest) []InventoryObservation {
	t.Helper()
	result := make([]InventoryObservation, len(request.Bindings))
	for index, binding := range request.Bindings {
		commitment, err := ObservationCommitmentSHA256(request, syntheticRunNonce(), binding, []byte("canonical-synthetic-value-"+base26(index)))
		if err != nil {
			t.Fatal(err)
		}
		result[index] = InventoryObservation{
			BindingClass:                binding.BindingClass,
			Reference:                   binding.Reference,
			ObservationCommitmentSHA256: commitment,
		}
	}
	return result
}

func syntheticRunNonce() []byte {
	return bytes.Repeat([]byte{0x5a}, ObservationNonceBytes)
}

func assertClassCount(t *testing.T, bindings []InventoryBinding, class BindingClass, expected int) {
	t.Helper()
	count := 0
	for _, binding := range bindings {
		if binding.BindingClass == class {
			count++
		}
	}
	if count != expected {
		t.Fatalf("binding class %q count = %d, want %d", class, count, expected)
	}
}

func testDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func base26(value int) string {
	var result strings.Builder
	for {
		result.WriteByte(byte('a' + value%26))
		value = value/26 - 1
		if value < 0 {
			break
		}
	}
	runes := []rune(result.String())
	slices.Reverse(runes)
	return string(runes)
}
