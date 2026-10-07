// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package ocs

import (
	"strings"
	"testing"
)

func Test_ConnectorPackageValidate_accepts_local_remote_and_api_only_profiles(t *testing.T) {
	tests := []struct {
		name string
		pkg  ConnectorPackage
	}{
		{name: "local without implementation binding", pkg: minimalProfilePackage(ExecutionProfileLocal)},
		{name: "remote", pkg: minimalProfilePackage(ExecutionProfileRemote)},
		{name: "independent non-billable API only", pkg: nonBillableAPIOnlyPackage()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.pkg.Validate(); err != nil {
				t.Fatalf("expected %s package to validate: %v", tt.name, err)
			}
		})
	}
}

func Test_ConnectorPackageValidate_rejects_missing_public_product_API(t *testing.T) {
	pkg := minimalProfilePackage(ExecutionProfileRemote)
	pkg.Service.Spec.ProductAPI = ProductAPIContract{}

	err := pkg.Validate()
	if err == nil {
		t.Fatal("expected missing public product API to fail")
	}
	for _, want := range []string{"productAPI.ref", "productAPI.version", "productAPI.protocol"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}

func Test_ConnectorPackageValidate_rejects_invalid_lifecycle_applicability(t *testing.T) {
	pkg := minimalProfilePackage(ExecutionProfileLocal)
	pkg.Service.Spec.Lifecycle[0].Applicability = "sometimes"

	err := pkg.Validate()
	if err == nil {
		t.Fatal("expected invalid lifecycle applicability to fail")
	}
	if !strings.Contains(err.Error(), "lifecycle[0].applicability must be supported or not_applicable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_ConnectorPackageValidate_rejects_opted_in_incomplete_federation(t *testing.T) {
	pkg := minimalProfilePackage(ExecutionProfileRemote)
	pkg.Federation = FederationProfile{Applicability: ApplicabilitySupported}

	err := pkg.Validate()
	if err == nil {
		t.Fatal("expected incomplete opted-in federation to fail")
	}
	for _, want := range []string{"federation.modes", "federation.messageBusRef", "federation.portabilityPolicyRef"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}

func Test_ConnectorPackageValidate_rejects_missing_or_raw_remote_connection_refs(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		pkg := minimalProfilePackage(ExecutionProfileRemote)
		pkg.Service.Spec.ProductAPI.EndpointRef = ""
		pkg.Service.Spec.ProductAPI.TrustPolicyRef = ""
		pkg.Service.Spec.ProductAPI.HealthRef = ""

		err := pkg.Validate()
		if err == nil {
			t.Fatal("expected missing remote connection references to fail")
		}
		for _, want := range []string{"productAPI.endpointRef", "productAPI.trustPolicyRef", "productAPI.healthRef"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("expected %q in error %q", want, err.Error())
			}
		}
	})

	t.Run("raw endpoint", func(t *testing.T) {
		pkg := minimalProfilePackage(ExecutionProfileAPIOnly)
		pkg.Service.Spec.ProductAPI.EndpointRef = "https://service.example.invalid/api"

		err := pkg.Validate()
		if err == nil {
			t.Fatal("expected raw endpoint value to fail")
		}
		if !strings.Contains(err.Error(), "productAPI.endpointRef must be a source-safe reference") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func Test_ConnectorPackageValidate_enforces_structured_product_API_references(t *testing.T) {
	t.Run("valid symbolic reference", func(t *testing.T) {
		pkg := minimalProfilePackage(ExecutionProfileRemote)
		pkg.Service.Spec.ProductAPI.EndpointRef = "connection.endpoint.synthetic-service"

		if err := pkg.Validate(); err != nil {
			t.Fatalf("expected symbolic product API references to validate: %v", err)
		}
	})

	for _, tt := range []struct {
		name  string
		value string
	}{
		{name: "IP port and path", value: "10." + "0.0.1:443/private-api"},
		{name: "absolute filesystem path", value: "/etc/cloudring/private-api"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pkg := minimalProfilePackage(ExecutionProfileRemote)
			pkg.Service.Spec.ProductAPI.EndpointRef = tt.value

			err := pkg.Validate()
			if err == nil {
				t.Fatalf("expected unsafe reference %q to fail", tt.value)
			}
			if !strings.Contains(err.Error(), "productAPI.endpointRef must be a source-safe reference") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func Test_ConnectorPackageValidate_requires_compatible_dependency_contract(t *testing.T) {
	t.Run("missing compatibility fields", func(t *testing.T) {
		pkg := minimalProfilePackage(ExecutionProfileLocal)
		dependency := &pkg.Service.Spec.Dependencies[0]
		dependency.ProductAPIRef = ""
		dependency.VersionRange = ""
		dependency.CompatibilityPolicyRef = ""

		err := pkg.Validate()
		if err == nil {
			t.Fatal("expected missing dependency compatibility fields to fail")
		}
		for _, want := range []string{"dependencies[0].productAPIRef", "dependencies[0].versionRange", "dependencies[0].compatibilityPolicyRef"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("expected %q in error %q", want, err.Error())
			}
		}
	})

	t.Run("invalid references and unbounded version", func(t *testing.T) {
		pkg := minimalProfilePackage(ExecutionProfileLocal)
		dependency := &pkg.Service.Spec.Dependencies[0]
		dependency.ProductAPIRef = "service/api/private"
		dependency.VersionRange = ">=1.0.0"
		dependency.CompatibilityPolicyRef = "policy:compatibility"

		err := pkg.Validate()
		if err == nil {
			t.Fatal("expected undecidable dependency compatibility to fail")
		}
		for _, want := range []string{
			"dependencies[0].productAPIRef must be a structured reference",
			"dependencies[0].versionRange must be a bounded range",
			"dependencies[0].compatibilityPolicyRef must be a structured reference",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("expected %q in error %q", want, err.Error())
			}
		}
	})
}

func Test_ConnectorPackageValidate_rejects_incomplete_optional_microfrontend(t *testing.T) {
	pkg := validConnectorPackage()
	pkg.Service.Spec.UI.ModuleHost.SignatureRef = ""

	err := pkg.Validate()
	if err == nil {
		t.Fatal("expected incomplete declared microfrontend to fail")
	}
	if !strings.Contains(err.Error(), "ui.moduleHost.signatureRef") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_ConnectorPackageValidate_rejects_Kubernetes_binding_outside_local_profile(t *testing.T) {
	pkg := validConnectorPackage()
	pkg.Service.Spec.ExecutionProfile = ExecutionProfileRemote

	err := pkg.Validate()
	if err == nil {
		t.Fatal("expected remote Kubernetes binding to fail")
	}
	if !strings.Contains(err.Error(), "kubernetesBindings must be omitted for remote execution profile") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_ConnectorPackageValidate_rejects_incomplete_supported_billing(t *testing.T) {
	pkg := minimalProfilePackage(ExecutionProfileRemote)
	pkg.Service.Spec.Billing.ConnectorRef = ""
	pkg.Billing.CostMeters = nil
	pkg.Billing.Events = nil

	err := pkg.Validate()
	if err == nil {
		t.Fatal("expected incomplete supported billing to fail")
	}
	for _, want := range []string{"billing.connectorRef", "costMeters", "events"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}

func Test_ConnectorPackageValidate_rejects_metadata_for_not_applicable_profiles(t *testing.T) {
	pkg := minimalProfilePackage(ExecutionProfileLocal)
	pkg.Federation.Modes = []string{"standalone"}
	pkg.Commercial.Roles = []string{"provider"}

	err := pkg.Validate()
	if err == nil {
		t.Fatal("expected stray not-applicable profile metadata to fail")
	}
	for _, want := range []string{
		"federation metadata must be omitted when applicability is not_applicable",
		"commercial metadata must be omitted when applicability is not_applicable",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}

func Test_ConnectorPackageValidate_rejects_missing_not_applicable_profile_reasons(t *testing.T) {
	pkg := minimalProfilePackage(ExecutionProfileLocal)
	pkg.Federation.Reason = ""
	pkg.Commercial.Reason = ""

	err := pkg.Validate()
	if err == nil {
		t.Fatal("expected missing not-applicable reasons to fail")
	}
	for _, want := range []string{"federation.reason", "commercial.reason"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}

func Test_ConnectorPackageValidate_rejects_executable_not_applicable_lifecycle(t *testing.T) {
	pkg := minimalProfilePackage(ExecutionProfileLocal)
	pkg.Service.Spec.Lifecycle[1].Verb = "Hold"
	pkg.Service.Spec.Lifecycle[1].Idempotent = true
	pkg.Service.Spec.Lifecycle[1].IdempotencyKey = "request.id"
	pkg.Service.Spec.Lifecycle[1].RollbackRef = "lifecycle.resume"

	err := pkg.Validate()
	if err == nil {
		t.Fatal("expected executable not-applicable lifecycle action to fail")
	}
	if !strings.Contains(err.Error(), "must not declare executable fields when applicability is not_applicable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func minimalProfilePackage(profile string) ConnectorPackage {
	pkg := validConnectorPackage()
	pkg.Service.Spec.ExecutionProfile = profile
	pkg.Service.Spec.KubernetesBindings = nil
	pkg.Service.Spec.PortalModules = nil
	pkg.Service.Spec.UI = UIExtensionManifest{}
	pkg.Federation = FederationProfile{
		Applicability: ApplicabilityNotApplicable,
		Reason:        "single-provider package",
	}
	pkg.Commercial = CommercialProfile{
		Applicability: ApplicabilityNotApplicable,
		Reason:        "noncommercial package",
	}
	pkg.Service.Spec.DataLifecycle.Export = DataLifecycleAction{}
	pkg.Service.Spec.Lifecycle = removeAction(pkg.Service.Spec.Lifecycle, "export")
	if profile == ExecutionProfileRemote || profile == ExecutionProfileAPIOnly {
		pkg.Service.Spec.ProductAPI.EndpointRef = "connection.endpoint.synthetic-service"
		pkg.Service.Spec.ProductAPI.TrustPolicyRef = "policy.trust.synthetic-service"
		pkg.Service.Spec.ProductAPI.HealthRef = "health.synthetic-service"
	}
	return pkg
}

func nonBillableAPIOnlyPackage() ConnectorPackage {
	pkg := minimalProfilePackage(ExecutionProfileAPIOnly)
	pkg.Service.Spec.Dependencies = nil
	pkg.Service.Spec.AnalyticsEvents = nil
	pkg.Service.Spec.UsageMeters = nil
	pkg.Service.Spec.Billing = BillingProfile{
		Applicability: ApplicabilityNotApplicable,
		Reason:        "this public API is provided without usage charging",
	}
	pkg.Billing = BillingConnector{}
	pkg.Catalog.Plans[0].BillingMode = "not-applicable"
	return pkg
}

func removeAction(actions []LifecycleAction, name string) []LifecycleAction {
	out := make([]LifecycleAction, 0, len(actions))
	for _, action := range actions {
		if action.Name != name {
			out = append(out, action)
		}
	}
	return out
}
