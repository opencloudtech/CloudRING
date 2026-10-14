// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package providerports

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAllCategoriesAndValidators(t *testing.T) {
	categories := AllServiceCategories()
	if len(categories) != 9 {
		t.Fatalf("expected 9 service categories, got %d", len(categories))
	}
	for _, cat := range categories {
		if !ValidServiceCategory(cat) {
			t.Fatalf("expected category %q to be valid", cat)
		}
	}
	if ValidServiceCategory("unknown-service") {
		t.Fatal("expected unknown category to be invalid")
	}
	if !ValidBackendFamily(BackendKubeVirt) || !ValidBackendFamily(BackendOpenStack) ||
		!ValidBackendFamily(BackendProxmox) || !ValidBackendFamily(BackendBareMetal) ||
		ValidBackendFamily("hyperv") {
		t.Fatal("unexpected BackendFamily validation result")
	}
	if !ValidLifecycleVerb(VerbProvision) || !ValidLifecycleVerb(VerbDeprovision) || ValidLifecycleVerb("reboot") {
		t.Fatal("unexpected LifecycleVerb validation result")
	}
	if !ValidResourceState(StateReady) || !ValidResourceState(StateBlocked) || ValidResourceState("bogus") {
		t.Fatal("unexpected ResourceState validation result")
	}
	if !ValidHealthStatus(HealthReady) || !ValidHealthStatus(HealthDegraded) || !ValidHealthStatus(HealthUnavailable) || ValidHealthStatus("unknown") {
		t.Fatal("unexpected HealthStatus validation result")
	}
}

func TestProvisionRequestAndReceiptValidation(t *testing.T) {
	req, err := NewProvisionRequest(
		ServiceCompute,
		"adapter-kubevirt-01",
		"tenant-alpha",
		"project-main",
		"vm-instance-01",
		"idem-key-001",
		VerbProvision,
		map[string]string{
			"zone":  "eu-central-1a",
			"cores": "4",
		},
	)
	if err != nil {
		t.Fatalf("unexpected NewProvisionRequest error: %v", err)
	}
	if len(req.Parameters) != 2 || req.Parameters[0].Key != "cores" || req.Parameters[1].Key != "zone" {
		t.Fatalf("expected sorted parameters, got %+v", req.Parameters)
	}

	// Invalid request cases
	if _, err := NewProvisionRequest("invalid", "adapter-01", "tenant-01", "project-01", "res-01", "idem-01", VerbProvision, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}

	unsortedReq := req
	unsortedReq.Parameters = []Parameter{{Key: "z", Value: "1"}, {Key: "a", Value: "2"}}
	if err := ValidateProvisionRequest(unsortedReq); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for unsorted parameters, got %v", err)
	}

	emptyValReq := req
	emptyValReq.Parameters = []Parameter{{Key: "valid_key", Value: "   "}}
	if err := ValidateProvisionRequest(emptyValReq); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for whitespace value, got %v", err)
	}

	tooManyParams := make(map[string]string, MaxParametersCount+1)
	for i := range MaxParametersCount + 1 {
		tooManyParams["k"+string(rune('a'+i/26))+string(rune('a'+i%26))] = "val"
	}
	if _, err := NewProvisionRequest(ServiceCompute, "adapter-01", "tenant-01", "project-01", "res-01", "idem-01", VerbProvision, tooManyParams); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for >MaxParametersCount, got %v", err)
	}

	if _, err := RequestSHA256(unsortedReq); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected RequestSHA256 error on invalid request, got %v", err)
	}
	if _, err := ReceiptCommitmentSHA256(unsortedReq, StateReady, "handle-01"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ReceiptCommitmentSHA256 error on invalid request, got %v", err)
	}
	if _, err := ReceiptCommitmentSHA256(req, "invalid-state", "handle-01"); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("expected ErrInvalidReceipt on invalid state, got %v", err)
	}
	if _, err := ReceiptCommitmentSHA256(req, StateReady, "bad..handle"); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("expected ErrInvalidReceipt on invalid handle, got %v", err)
	}

	// Receipt construction & validation
	if _, err := NewProvisionReceipt(unsortedReq, "op-001", StateReady, "handle-01", ""); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("expected ErrInvalidReceipt when request is invalid, got %v", err)
	}
	if _, err := NewProvisionReceipt(req, "op-001", "bad-state", "handle-01", ""); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("expected ErrInvalidReceipt when commitment fails, got %v", err)
	}
	if _, err := NewProvisionReceipt(req, "op-001", StateReady, "handle-01", "unexpected-blocker"); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("expected ErrInvalidReceipt when ready state has blocker, got %v", err)
	}
	if _, err := NewProvisionReceipt(req, "op-001", StateBlocked, "handle-01", ""); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("expected ErrInvalidReceipt when blocked state misses blockerCode, got %v", err)
	}
	blockedReceipt, err := NewProvisionReceipt(req, "op-001", StateBlocked, "handle-01", "quota-exceeded")
	if err != nil {
		t.Fatalf("expected valid blocked receipt, got %v", err)
	}
	if err := ValidateProvisionReceipt(unsortedReq, blockedReceipt); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("expected ErrInvalidReceipt when validating against invalid request, got %v", err)
	}
	tampered := blockedReceipt
	tampered.TenantID = "tenant-other"
	if err := ValidateProvisionReceipt(req, tampered); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("expected ErrInvalidReceipt on tampered tenant, got %v", err)
	}
}

func TestProviderRegistryAndAllNineCategoryInterfaces(t *testing.T) {
	registry := NewProviderRegistry()
	if err := registry.Register(nil); !errors.Is(err, ErrInvalidAdapterDescriptor) {
		t.Fatalf("expected ErrInvalidAdapterDescriptor on nil port, got %v", err)
	}
	if _, err := NewInMemoryAdapter("bad..id", ServiceCompute, BackendKubeVirt); !errors.Is(err, ErrInvalidAdapterDescriptor) {
		t.Fatalf("expected ErrInvalidAdapterDescriptor on bad adapterID, got %v", err)
	}

	backends := []BackendFamily{BackendKubeVirt, BackendOpenStack, BackendProxmox, BackendBareMetal}
	for i, cat := range AllServiceCategories() {
		family := backends[i%len(backends)]
		adapterID := "adapter-" + string(cat)
		adapter, err := NewInMemoryAdapter(adapterID, cat, family)
		if err != nil {
			t.Fatalf("NewInMemoryAdapter(%s): %v", cat, err)
		}
		if err := registry.Register(adapter); err != nil {
			t.Fatalf("Register(%s): %v", cat, err)
		}
		if err := registry.Register(adapter); !errors.Is(err, ErrAdapterAlreadyRegistered) {
			t.Fatalf("expected ErrAdapterAlreadyRegistered for %s, got %v", cat, err)
		}

		res, err := RunConformanceSuite(adapter)
		if err != nil || !res.Passed || len(res.VerifiedChecks) != 6 {
			t.Fatalf("RunConformanceSuite(%s) failed: res=%+v err=%v", cat, res, err)
		}
	}

	// Add a second compute adapter to exercise same-category tie-breaking in List()
	extraCompute, err := NewInMemoryAdapter("adapter-compute-zzz", ServiceCompute, BackendOpenStack)
	if err != nil {
		t.Fatalf("NewInMemoryAdapter: %v", err)
	}
	if err := registry.Register(extraCompute); err != nil {
		t.Fatalf("Register extraCompute: %v", err)
	}

	listed := registry.List()
	if len(listed) != 10 {
		t.Fatalf("expected 10 registered adapters, got %d", len(listed))
	}
	for i := 1; i < len(listed); i++ {
		prev, curr := listed[i-1], listed[i]
		if prev.ServiceCategory > curr.ServiceCategory ||
			(prev.ServiceCategory == curr.ServiceCategory && prev.AdapterID >= curr.AdapterID) {
			t.Fatalf("registry List() not sorted at index %d: %+v vs %+v", i, prev, curr)
		}
	}

	if _, err := registry.Lookup("invalid-cat", "adapter-compute"); !errors.Is(err, ErrInvalidAdapterDescriptor) {
		t.Fatalf("expected ErrInvalidAdapterDescriptor, got %v", err)
	}
	if _, err := registry.Lookup(ServiceCompute, "adapter-missing"); !errors.Is(err, ErrAdapterNotFound) {
		t.Fatalf("expected ErrAdapterNotFound, got %v", err)
	}

	// Verify all 9 specialized category methods and lifecycle verbs
	ctx := context.Background()
	verifyCategoryCall := func(cat ServiceCategory, invoke func(a *InMemoryAdapter, req ProvisionRequest) (ProvisionReceipt, error)) {
		port, err := registry.Lookup(cat, "adapter-"+string(cat))
		if err != nil {
			t.Fatalf("Lookup(%s): %v", cat, err)
		}
		mem := port.(*InMemoryAdapter)
		req, err := NewProvisionRequest(cat, mem.AdapterID(), "tenant-x", "proj-x", "res-cat-01", "idem-cat-01", VerbProvision, nil)
		if err != nil {
			t.Fatalf("NewProvisionRequest(%s): %v", cat, err)
		}
		receipt, err := invoke(mem, req)
		if err != nil || receipt.State != StateReady {
			t.Fatalf("category invoke(%s) failed: receipt=%+v err=%v", cat, receipt, err)
		}
	}

	verifyCategoryCall(ServiceCompute, func(a *InMemoryAdapter, r ProvisionRequest) (ProvisionReceipt, error) {
		var p ComputeProvider = a
		return p.ProvisionInstance(ctx, r)
	})
	verifyCategoryCall(ServiceVolume, func(a *InMemoryAdapter, r ProvisionRequest) (ProvisionReceipt, error) {
		var p VolumeProvider = a
		return p.ProvisionVolume(ctx, r)
	})
	verifyCategoryCall(ServiceNetwork, func(a *InMemoryAdapter, r ProvisionRequest) (ProvisionReceipt, error) {
		var p NetworkProvider = a
		return p.ProvisionNetwork(ctx, r)
	})
	verifyCategoryCall(ServiceKubernetes, func(a *InMemoryAdapter, r ProvisionRequest) (ProvisionReceipt, error) {
		var p KubernetesClusterProvider = a
		return p.ProvisionCluster(ctx, r)
	})
	verifyCategoryCall(ServiceObjectStorage, func(a *InMemoryAdapter, r ProvisionRequest) (ProvisionReceipt, error) {
		var p ObjectStorageProvider = a
		return p.ProvisionBucket(ctx, r)
	})
	verifyCategoryCall(ServiceBackup, func(a *InMemoryAdapter, r ProvisionRequest) (ProvisionReceipt, error) {
		var p BackupProvider = a
		return p.ProvisionBackupPlan(ctx, r)
	})
	verifyCategoryCall(ServiceAccessControl, func(a *InMemoryAdapter, r ProvisionRequest) (ProvisionReceipt, error) {
		var p AccessControlProvider = a
		return p.ProvisionAccessPolicy(ctx, r)
	})
	verifyCategoryCall(ServiceSupport, func(a *InMemoryAdapter, r ProvisionRequest) (ProvisionReceipt, error) {
		var p SupportProvider = a
		return p.ProvisionSupportSubscription(ctx, r)
	})
	verifyCategoryCall(ServiceExternalIntegration, func(a *InMemoryAdapter, r ProvisionRequest) (ProvisionReceipt, error) {
		var p ExternalIntegrationProvider = a
		return p.ProvisionExternalConnector(ctx, r)
	})
}

func TestInMemoryAdapterLifecycleAndEdgeCases(t *testing.T) {
	adapter, err := NewInMemoryAdapter("adapter-compute", ServiceCompute, BackendKubeVirt)
	if err != nil {
		t.Fatalf("NewInMemoryAdapter: %v", err)
	}
	ctx := context.Background()

	// Health transitions
	if err := adapter.SetHealth(HealthDegraded, ""); !errors.Is(err, ErrInvalidHealthStatus) {
		t.Fatalf("expected ErrInvalidHealthStatus when degraded has no reason, got %v", err)
	}
	if err := adapter.SetHealth(HealthDegraded, "storage-latency-elevated"); err != nil {
		t.Fatalf("SetHealth failed: %v", err)
	}
	// Context nil check
	//nolint:staticcheck // intentionally testing nil context guard
	if _, err := adapter.Health(nil); !errors.Is(err, ErrContextCanceled) {
		t.Fatalf("expected ErrContextCanceled on nil context, got %v", err)
	}

	// Non-existent resource for non-provision verb
	resizeMissing, _ := NewProvisionRequest(ServiceCompute, "adapter-compute", "tenant-a", "proj-a", "missing-vm", "idem-1", VerbResize, nil)
	if _, err := adapter.ExecuteLifecycle(ctx, resizeMissing); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("expected ErrResourceNotFound for resize on missing resource, got %v", err)
	}

	// Invalid request to ExecuteLifecycle
	if _, err := adapter.ExecuteLifecycle(ctx, ProvisionRequest{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}

	// Mismatched adapterID in request
	wrongAdapterReq, _ := NewProvisionRequest(ServiceCompute, "other-adapter", "tenant-a", "proj-a", "vm-01", "idem-1", VerbProvision, nil)
	if _, err := adapter.ExecuteLifecycle(ctx, wrongAdapterReq); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for wrong adapterID, got %v", err)
	}

	// Provision -> Suspend -> Resume -> Deprovision
	provReq, _ := NewProvisionRequest(ServiceCompute, "adapter-compute", "tenant-a", "proj-a", "vm-01", "idem-prov", VerbProvision, nil)
	if _, err := adapter.ExecuteLifecycle(ctx, provReq); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	suspReq, _ := NewProvisionRequest(ServiceCompute, "adapter-compute", "tenant-a", "proj-a", "vm-01", "idem-susp", VerbSuspend, nil)
	suspRec, err := adapter.ExecuteLifecycle(ctx, suspReq)
	if err != nil || suspRec.State != StateSuspended {
		t.Fatalf("Suspend failed: %+v %v", suspRec, err)
	}
	deprovReq, _ := NewProvisionRequest(ServiceCompute, "adapter-compute", "tenant-a", "proj-a", "vm-01", "idem-deprov", VerbDeprovision, nil)
	deprovRec, err := adapter.ExecuteLifecycle(ctx, deprovReq)
	if err != nil || deprovRec.State != StateDeleted {
		t.Fatalf("Deprovision failed: %+v %v", deprovRec, err)
	}

	// InspectResource edge cases
	//nolint:staticcheck // intentionally testing nil context guard
	if _, err := adapter.InspectResource(nil, "tenant-a", "proj-a", "vm-01"); !errors.Is(err, ErrContextCanceled) {
		t.Fatalf("expected ErrContextCanceled on InspectResource with nil ctx, got %v", err)
	}
	if _, err := adapter.InspectResource(ctx, "bad..id", "proj-a", "vm-01"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest on bad identifier, got %v", err)
	}
	if _, err := adapter.InspectResource(ctx, "tenant-a", "proj-a", "unknown-vm"); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("expected ErrResourceNotFound on unknown resource, got %v", err)
	}
	inspected, err := adapter.InspectResource(ctx, "tenant-a", "proj-a", "vm-01")
	if err != nil || inspected.State != StateDeleted {
		t.Fatalf("InspectResource unexpected result: %+v %v", inspected, err)
	}

	// Long resourceID (>50 chars) causes opID in ExecuteLifecycle to exceed 64-char identifier limit
	longResourceID := "res-" + strings.Repeat("a", 55)
	longReq, err := NewProvisionRequest(ServiceCompute, "adapter-compute", "tenant-a", "proj-a", longResourceID, "idem-long", VerbProvision, nil)
	if err != nil {
		t.Fatalf("unexpected NewProvisionRequest error: %v", err)
	}
	if _, err := adapter.ExecuteLifecycle(ctx, longReq); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("expected ErrInvalidReceipt when generated opID exceeds 64 chars, got %v", err)
	}
}

type faultyPort struct {
	*InMemoryAdapter
	mode string
	calls int
}

func (f *faultyPort) Health(ctx context.Context) (HealthReport, error) {
	switch f.mode {
	case "health-err":
		return HealthReport{}, errors.New("simulated health error")
	case "health-invalid":
		return HealthReport{AdapterID: "bad..id"}, nil
	default:
		return f.InMemoryAdapter.Health(ctx)
	}
}

func (f *faultyPort) ExecuteLifecycle(ctx context.Context, req ProvisionRequest) (ProvisionReceipt, error) {
	f.calls++
	switch f.mode {
	case "exec-err":
		return ProvisionReceipt{}, errors.New("simulated exec error")
	case "exec-bad-receipt":
		return ProvisionReceipt{SchemaVersion: "bad"}, nil
	case "replay-err":
		if f.calls == 2 {
			return ProvisionReceipt{}, errors.New("simulated replay error")
		}
		return f.InMemoryAdapter.ExecuteLifecycle(ctx, req)
	case "non-deterministic-replay":
		rec, err := f.InMemoryAdapter.ExecuteLifecycle(ctx, req)
		if f.calls == 2 {
			rec.OperationID = "op-mutated-on-replay"
		}
		return rec, err
	case "ignore-conflict":
		rec, _ := NewProvisionReceipt(req, "op-conflict-ignored", StateReady, "handle-ok", "")
		return rec, nil
	case "allow-cross-tenant-mutate":
		if req.TenantID == "tenant-bravo" {
			rec, _ := NewProvisionReceipt(req, "op-leaked", StateDeleted, "handle-ok", "")
			return rec, nil
		}
		return f.InMemoryAdapter.ExecuteLifecycle(ctx, req)
	case "ignore-context-cancel":
		return f.InMemoryAdapter.ExecuteLifecycle(context.Background(), req)
	default:
		return f.InMemoryAdapter.ExecuteLifecycle(ctx, req)
	}
}

func (f *faultyPort) InspectResource(ctx context.Context, tenantID, projectID, resourceID string) (ProvisionReceipt, error) {
	if f.mode == "allow-cross-tenant-inspect" {
		return ProvisionReceipt{}, nil
	}
	return f.InMemoryAdapter.InspectResource(ctx, tenantID, projectID, resourceID)
}

func TestRunConformanceSuiteFailureModes(t *testing.T) {
	if _, err := RunConformanceSuite(nil); !errors.Is(err, ErrInvalidAdapterDescriptor) {
		t.Fatalf("expected ErrInvalidAdapterDescriptor on nil port, got %v", err)
	}

	badIDBase, _ := NewInMemoryAdapter("adapter-ok", ServiceCompute, BackendKubeVirt)
	badIDBase.adapterID = "bad..id"
	if _, err := RunConformanceSuite(badIDBase); !errors.Is(err, ErrInvalidHealthStatus) {
		t.Fatalf("expected ErrInvalidHealthStatus on bad adapter ID in health, got %v", err)
	}

	modes := []string{
		"health-err",
		"health-invalid",
		"exec-err",
		"exec-bad-receipt",
		"replay-err",
		"non-deterministic-replay",
		"ignore-conflict",
		"allow-cross-tenant-inspect",
		"allow-cross-tenant-mutate",
		"ignore-context-cancel",
	}
	for _, mode := range modes {
		base, _ := NewInMemoryAdapter("adapter-compute", ServiceCompute, BackendKubeVirt)
		fp := &faultyPort{InMemoryAdapter: base, mode: mode}
		if _, err := RunConformanceSuite(fp); err == nil {
			t.Fatalf("expected RunConformanceSuite to fail for mode %q", mode)
		}
	}

	// Also test when NewProvisionRequest inside RunConformanceSuite fails (health passes via custom override)
	customPort := &customHealthBadIDPort{InMemoryAdapter: badIDBase}
	if _, err := RunConformanceSuite(customPort); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest when port.AdapterID() is invalid, got %v", err)
	}
}

type customHealthBadIDPort struct {
	*InMemoryAdapter
}

func (c *customHealthBadIDPort) Health(_ context.Context) (HealthReport, error) {
	return HealthReport{
		AdapterID:       "adapter-valid",
		ServiceCategory: ServiceCompute,
		BackendFamily:   BackendKubeVirt,
		Status:          HealthReady,
	}, nil
}
