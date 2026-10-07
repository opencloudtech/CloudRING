// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package ocs

import (
	"encoding/json"
	"strings"
	"testing"
)

func Test_ServiceConnectorValidate_accepts_declarative_kubernetes_connector(t *testing.T) {
	connector := validServiceConnector()

	if err := connector.Validate(); err != nil {
		t.Fatalf("expected connector to validate: %v", err)
	}
}

func Test_ServiceConnectorValidate_allows_omitted_portal_but_rejects_missing_billing_surfaces(t *testing.T) {
	connector := validServiceConnector()
	connector.Spec.PortalModules = nil
	connector.Spec.UI = UIExtensionManifest{}
	connector.Spec.Billing.Meters = nil

	err := connector.Validate()
	if err == nil {
		t.Fatal("expected missing portal and billing surfaces to fail")
	}
	for _, want := range []string{"billing.meters"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}

func Test_ConnectorPackageValidate_accepts_parallel_service_package(t *testing.T) {
	pkg := validConnectorPackage()

	if err := pkg.Validate(); err != nil {
		t.Fatalf("expected connector package to validate: %v", err)
	}
}

func Test_ConnectorPackageValidate_rejects_missing_portable_surfaces(t *testing.T) {
	pkg := validConnectorPackage()
	pkg.Catalog.Plans = nil
	pkg.Configuration.SchemaRef = ""
	pkg.Readiness = nil
	pkg.TenantAccess.Permissions = nil
	pkg.Durability.DataClasses = nil
	pkg.Service.Spec.Dependencies[0].Portability = "implementation-specific"
	pkg.Service.Spec.Automation[0].ActionRef = "lifecycle.missing"
	pkg.Service.Spec.Billing.Meters = []UsageMeter{{Name: "missing_meter", Unit: "unit"}}

	err := pkg.Validate()
	if err == nil {
		t.Fatal("expected missing package surfaces to fail")
	}
	for _, want := range []string{
		"catalog.plans",
		"configuration.schemaRef",
		"readiness",
		"tenantAccess.permissions",
		"durability.dataClasses",
		"portability",
		"automation[0].actionRef",
		"billing.meters",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}

func Test_BillingConnectorValidate_rejects_unknown_meter_reference(t *testing.T) {
	connector := BillingConnector{
		APIVersion: APIVersion,
		Kind:       "BillingConnector",
		Metadata: Metadata{
			Name:        "object-storage-billing",
			DisplayName: "Object Storage Billing",
			Owner:       "storage-team",
			Version:     "v0.1.0",
		},
		Meters: []UsageMeter{{Name: "stored_bytes", Unit: "byte-hour"}},
		CostMeters: []CostMeter{{
			Name:        "storage_gib_month",
			Currency:    "USD",
			UnitPrice:   "0.00-example",
			MeterRef:    "stored_bytes",
			EvidenceRef: "evidence.object-storage.cost-meter",
		}},
		Events: []BillingEvent{{
			Name:           "egress-recorded",
			Meter:          "missing_meter",
			Idempotent:     true,
			IdempotencyKey: "usageEvent.id",
			EntitlementRef: "catalog.plan.standard",
			Attribution:    "tenant.project.subscription",
			ReplayPolicy:   "dedupe-by-idempotency-key",
		}},
	}

	err := connector.Validate()
	if err == nil {
		t.Fatal("expected unknown meter reference to fail")
	}
	if !strings.Contains(err.Error(), "events[0].meterRef") {
		t.Fatalf("expected meter reference error, got %q", err.Error())
	}
}

func Test_ServiceConnectorValidate_rejects_missing_idempotency_contract(t *testing.T) {
	connector := validServiceConnector()
	for i := range connector.Spec.Lifecycle {
		connector.Spec.Lifecycle[i].IdempotencyKey = ""
	}

	err := connector.Validate()
	if err == nil {
		t.Fatal("expected missing idempotency contracts to fail")
	}
	for _, want := range []string{"lifecycle[0].idempotencyKey", "lifecycle[4].idempotencyKey"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}

func Test_ConnectorPackageValidate_rejects_missing_declarative_kubernetes_surfaces(t *testing.T) {
	raw := `{
		"apiVersion": "ocsv3.cloudring.io/v1alpha1",
		"kind": "ConnectorPackage",
		"metadata": {"name": "object-storage-package", "displayName": "Object Storage Package", "owner": "storage-team", "version": "v0.1.0"},
		"service": {
			"apiVersion": "ocsv3.cloudring.io/v1alpha1",
			"kind": "ServiceConnector",
			"metadata": {"name": "object-storage", "displayName": "Object Storage", "owner": "storage-team", "version": "v0.1.0"},
			"spec": {
				"capabilities": [{"class": "object-storage", "name": "bucket"}],
				"lifecycle": [{"name": "provision", "verb": "Apply", "idempotent": true}],
				"automation": [{"name": "provision-bucket", "actionRef": "lifecycle.provision"}],
				"usageMeters": [{"name": "stored_bytes", "unit": "byte-hour"}],
				"billing": {"connectorRef": "object-storage-billing", "meters": [{"name": "stored_bytes", "unit": "byte-hour"}]},
				"portalModules": [{"name": "bucket-overview", "slot": "service.detail", "route": "/services/object-storage/buckets", "permissions": ["object-storage.read"]}],
				"kubernetesBindings": [{"group": "storage.cloudring.io", "version": "v1alpha1", "kind": "ObjectBucket", "plural": "objectbuckets", "scope": "Namespaced", "condition": "Ready"}],
				"support": {"owner": "storage-team", "diagnostics": ["bucket-status"]}
			}
		},
		"billing": {
			"apiVersion": "ocsv3.cloudring.io/v1alpha1",
			"kind": "BillingConnector",
			"metadata": {"name": "object-storage-billing", "displayName": "Object Storage Billing", "owner": "storage-team", "version": "v0.1.0"},
			"meters": [{"name": "stored_bytes", "unit": "byte-hour"}],
			"events": [{"name": "storage-usage-recorded", "meter": "stored_bytes", "idempotent": true}]
		},
		"catalog": {"serviceClass": "object-storage", "visibility": "tenant", "portability": "export-import", "plans": [{"name": "standard", "displayName": "Standard Object Storage", "billingMode": "metered"}]},
		"configuration": {"schemaRef": "schemas/object-storage.v1alpha1.json", "version": "v1alpha1"},
		"readiness": [{"name": "bucket-controller-ready", "type": "kubernetes-condition", "target": "ObjectBucket.status.conditions", "condition": "Ready"}],
		"tenantAccess": {"scope": "project", "entitlementRef": "catalog.plan.standard", "permissions": ["object-storage.read"]},
		"durability": {"stateClass": "stateful", "dataClasses": ["tenant-object-data"], "recoveryObjective": "restore-test-required-before-production"}
	}`
	var pkg ConnectorPackage
	if err := json.Unmarshal([]byte(raw), &pkg); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	err := pkg.Validate()
	if err == nil {
		t.Fatal("expected missing declarative Kubernetes surfaces to fail")
	}
	for _, want := range []string{
		"kubernetesBindings[0].crdRef",
		"kubernetesBindings[0].statusPath",
		"readiness[0].evidenceRef",
		"tenantAccess.entitlements",
		"durability.recoveryEvidence",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}
