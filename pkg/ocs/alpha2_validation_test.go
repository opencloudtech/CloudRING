// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package ocs

import (
	"strings"
	"testing"
)

func Test_ConnectorPackageValidate_accepts_alpha2_module_surfaces(t *testing.T) {
	// Given
	pkg := validAlpha2ConnectorPackage()

	// When
	err := pkg.Validate()

	// Then
	if err != nil {
		t.Fatalf("expected OCSv3 package to validate: %v", err)
	}
}

func Test_ConnectorPackageValidate_rejects_missing_alpha2_evidence_when_required(t *testing.T) {
	// Given
	pkg := validAlpha2ConnectorPackage()
	pkg.Service.Spec.UI.Evidence = nil
	pkg.Service.Spec.Support.Evidence = nil
	pkg.Durability.RecoveryEvidence = nil
	pkg.Service.Spec.DataLifecycle.Export.EvidenceRef = ""

	// When
	err := pkg.Validate()

	// Then
	if err == nil {
		t.Fatal("expected missing OCSv3 evidence to fail")
	}
	for _, want := range []string{
		"class=ui owner=service path=ui.evidence",
		"class=support owner=service path=support.evidence",
		"class=durability owner=service path=durability.recoveryEvidence",
		"class=data owner=service path=dataLifecycle.export.evidenceRef",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}

func Test_ConnectorPackageValidate_rejects_missing_billing_cost_meter_evidence_with_actionable_envelope(t *testing.T) {
	// Given
	pkg := validAlpha2ConnectorPackage()
	pkg.Billing.CostMeters[0].EvidenceRef = ""

	// When
	err := pkg.Validate()

	// Then
	if err == nil {
		t.Fatal("expected missing billing cost meter evidence to fail")
	}
	for _, want := range []string{
		"class=billing",
		"owner=billing",
		"path=costMeters[0].evidenceRef",
		"remediation=",
		"impact=",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}

func Test_ConnectorPackageValidate_rejects_implementation_reference_and_single_vendor_lock_in(t *testing.T) {
	// Given
	pkg := validAlpha2ConnectorPackage()
	pkg.Service.Spec.Dependencies[0].ImplementationRef = "adapter.synthetic-service"
	pkg.Service.Spec.Dependencies[0].Portability = "single-vendor-binding"
	pkg.Service.Spec.GatewayRoutes[0].ParentRef = "single-vendor/gateway/private-route"

	// When
	err := pkg.Validate()

	// Then
	if err == nil {
		t.Fatal("expected implementation coupling and provider lock-in to fail")
	}
	for _, want := range []string{
		"class=portability owner=service path=service.spec.dependencies[0].portability",
		"class=coupling owner=service path=service.spec.dependencies[0].implementationRef",
		"class=provider-lock-in owner=service path=service.spec.gatewayRoutes[0].parentRef",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}

func Test_ConnectorPackageValidate_rejects_data_lifecycle_reference_to_not_applicable_action(t *testing.T) {
	// Given
	pkg := validAlpha2ConnectorPackage()
	for i := range pkg.Service.Spec.Lifecycle {
		if pkg.Service.Spec.Lifecycle[i].Name != "deprovision" {
			continue
		}
		pkg.Service.Spec.Lifecycle[i].Applicability = ApplicabilityNotApplicable
		pkg.Service.Spec.Lifecycle[i].Reason = "the product retains no customer data"
		pkg.Service.Spec.Lifecycle[i].Verb = ""
		pkg.Service.Spec.Lifecycle[i].Idempotent = false
		pkg.Service.Spec.Lifecycle[i].IdempotencyKey = ""
		pkg.Service.Spec.Lifecycle[i].RollbackRef = ""
	}

	// When
	err := pkg.Validate()

	// Then
	if err == nil {
		t.Fatal("expected a data lifecycle reference to a non-executable action to fail")
	}
	if !strings.Contains(err.Error(), "dataLifecycle.delete.actionRef") ||
		!strings.Contains(err.Error(), "must reference a supported lifecycle action") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func validAlpha2ConnectorPackage() ConnectorPackage {
	pkg := validConnectorPackage()
	pkg.Service.Spec.UI = UIExtensionManifest{
		EmbedRef:         "ui.object-storage.bundle",
		ContextSchemaRef: "schemas/object-storage-ui-context.v1alpha1.json",
		HostAuthority:    []string{"navigation", "identity", "policy"},
		ExtensionActions: []string{"bucket.create", "bucket.delete"},
		ModuleHost: MicrofrontendHostContract{
			Host:            "cloudring-provider-portal",
			Runtime:         "module-federation",
			MountRef:        "mount.object-storage.bucket-overview",
			VersionRange:    ">=0.1.0 <1.0.0",
			SignatureRef:    "evidence.object-storage.ui.signature",
			IntegrityRef:    "evidence.object-storage.ui.integrity",
			Sandbox:         "tenant-iam-context",
			AllowedEvents:   []string{"bucket.create.requested", "bucket.delete.requested"},
			RequiredContext: []string{"tenant", "project", "iam.subject", "locale", "theme"},
		},
		Evidence: []EvidenceRef{{
			Name: "ui-host-shell-certification",
			Type: "certification-evidence",
			Ref:  "evidence.object-storage.ui.host-shell",
		}},
	}
	pkg.Service.Spec.GatewayRoutes = []GatewayRoute{{
		Name:        "object-storage-api",
		ParentRef:   "gateway.platform.service-api",
		Hostnames:   []string{"object-storage.services.example"},
		Rules:       []string{"tenant-scoped-bucket-api"},
		EvidenceRef: "evidence.object-storage.gateway-route",
	}}
	pkg.Service.Spec.Secrets = SecretBoundary{
		WorkloadIdentityRef: "workloadidentity.object-storage-controller",
		SecretRefs: []SecretRef{{
			Name:     "s3-credential-reference",
			Ref:      "secretref.object-storage.access-key",
			Purpose:  "tenant data-plane access",
			Rotation: "operator-initiated",
		}},
	}
	pkg.Service.Spec.Policies = []PolicyRule{{
		Name:        "tenant-data-residency",
		Class:       "data-residency",
		DecisionRef: "policy.object-storage.residency",
		EvidenceRef: "evidence.object-storage.policy",
	}}
	pkg.Service.Spec.DataLifecycle = DataLifecycle{
		Export: DataLifecycleAction{
			ActionRef:   "lifecycle.export",
			Format:      "ocs-portable-archive",
			EvidenceRef: "evidence.object-storage.export",
		},
		Delete: DataLifecycleAction{
			ActionRef:   "lifecycle.deprovision",
			Format:      "tenant-object-delete-receipt",
			EvidenceRef: "evidence.object-storage.delete",
		},
	}
	pkg.Service.Spec.States = []ServiceState{{
		Name:        "degraded",
		Reason:      "backend capability unavailable",
		UserVisible: true,
		EvidenceRef: "evidence.object-storage.degraded",
		Remediation: "retry after capability recovery or export data",
	}, {
		Name:        "blocked",
		Reason:      "policy denial or missing entitlement",
		UserVisible: true,
		EvidenceRef: "evidence.object-storage.blocked",
		Remediation: "resolve policy or entitlement before retry",
	}}
	pkg.Service.Spec.Support.Evidence = []EvidenceRef{{
		Name: "support-diagnostics",
		Type: "support-evidence",
		Ref:  "evidence.object-storage.support-diagnostics",
	}}
	pkg.Service.Spec.EvidenceBundles = []EvidenceBundle{{
		Name:       "ocsv3-support-bundle",
		Owner:      "storage-team",
		Claim:      "support diagnostics, UI certification, policy, and data lifecycle evidence are linked",
		Freshness:  "review-before-publication",
		Redaction:  "support-safe-summary-only",
		Evidence:   []EvidenceRef{{Name: "support-diagnostics", Type: "support-evidence", Ref: "evidence.object-storage.support-diagnostics"}},
		NonClaims:  []string{"does not prove provider production readiness"},
		ReviewPath: "support.owner.review",
	}}
	pkg.Billing.CostMeters = []CostMeter{{
		Name:        "storage_gib_month",
		Currency:    "USD",
		UnitPrice:   "0.00-example",
		MeterRef:    "stored_bytes",
		EvidenceRef: "evidence.object-storage.cost-meter",
	}}
	return pkg
}
