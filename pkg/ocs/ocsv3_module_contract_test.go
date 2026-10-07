// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package ocs

import (
	"strings"
	"testing"
)

func Test_ConnectorPackageValidate_rejects_missing_microfrontend_host_contract(t *testing.T) {
	pkg := validConnectorPackage()
	pkg.Service.Spec.UI.ModuleHost = MicrofrontendHostContract{}

	err := pkg.Validate()
	if err == nil {
		t.Fatal("expected missing microfrontend host contract to fail")
	}
	for _, want := range []string{
		"ui.moduleHost.host",
		"ui.moduleHost.runtime",
		"ui.moduleHost.mountRef",
		"ui.moduleHost.integrityRef",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}

func Test_ConnectorPackageValidate_accepts_omitted_product_analytics_events(t *testing.T) {
	pkg := validConnectorPackage()
	pkg.Service.Spec.AnalyticsEvents = nil

	err := pkg.Validate()
	if err != nil {
		t.Fatalf("expected product analytics to be optional: %v", err)
	}
}

func Test_ServiceConnectorValidate_rejects_portal_module_without_host_binding(t *testing.T) {
	connector := validServiceConnector()
	connector.Spec.PortalModules[0].HostRef = ""
	connector.Spec.PortalModules[0].MountRef = ""

	err := connector.Validate()
	if err == nil {
		t.Fatal("expected missing portal module host binding to fail")
	}
	for _, want := range []string{
		"portalModules[0].hostRef",
		"portalModules[0].mountRef",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}
