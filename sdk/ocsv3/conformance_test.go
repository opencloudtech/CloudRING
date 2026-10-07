// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package ocsv3_test

import (
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/sdk/ocsv3"
)

func TestCheckConformance_passes_public_reference_without_mutation_claim(t *testing.T) {
	pkg, err := ocsv3.ParseConnectorPackage(readFixture(t, "../../reference/synthetic-service/module-package.json"))
	if err != nil {
		t.Fatalf("parse public reference package: %v", err)
	}

	report := ocsv3.CheckConformance(pkg)

	if !report.Passed {
		t.Fatalf("expected conformance to pass: %+v", report.Problems)
	}
	if !report.ProviderNeutral {
		t.Fatal("expected provider-neutral conformance result")
	}
	if report.ProductionMutate {
		t.Fatal("conformance must not claim or perform production mutation")
	}
	if len(report.Problems) != 0 {
		t.Fatalf("passing report contains problems: %+v", report.Problems)
	}
	if _, err := time.Parse(time.RFC3339, report.GeneratedAt); err != nil {
		t.Fatalf("generatedAt is not RFC3339: %q: %v", report.GeneratedAt, err)
	}
	for _, surface := range []string{"service", "billing", "portal", "iam", "durability", "federation"} {
		if !contains(report.CheckedSurfaces, surface) {
			t.Fatalf("checked surfaces missing %q: %v", surface, report.CheckedSurfaces)
		}
	}
}

func TestCheckConformance_reports_independent_surface_failures(t *testing.T) {
	pkg, err := ocsv3.ParseConnectorPackage(readFixture(t, "../../reference/synthetic-service/module-package.json"))
	if err != nil {
		t.Fatalf("parse public reference package: %v", err)
	}
	pkg.Service.Spec.Policies = nil
	pkg.Service.Spec.ProductAPI.Version = ""
	pkg.Service.Spec.Lifecycle = removeLifecycleAction(pkg.Service.Spec.Lifecycle, "resize")

	report := ocsv3.CheckConformance(pkg)

	if report.Passed {
		t.Fatal("expected incomplete package to fail conformance")
	}
	for _, field := range []string{
		"package",
		"service.spec.policies",
		"service.spec.productAPI.version",
		"service.spec.lifecycle.resize",
	} {
		if !hasProblem(report.Problems, field) {
			t.Fatalf("expected problem for %q: %+v", field, report.Problems)
		}
	}
	if report.ProductionMutate {
		t.Fatal("failed conformance must remain non-mutating")
	}
}

func TestBuildEvidenceReceipt_copies_report_and_preserves_non_claims(t *testing.T) {
	report := ocsv3.ConformanceReport{
		PackageName:     "synthetic-service",
		Passed:          true,
		Summary:         "synthetic package passed",
		CheckedSurfaces: []string{"schema", "iam"},
		NonClaims:       []string{"does not claim live production readiness"},
	}

	receipt := ocsv3.BuildEvidenceReceipt(report)
	report.CheckedSurfaces[0] = "mutated"
	report.NonClaims[0] = "mutated"

	if receipt.Status != "ok" {
		t.Fatalf("status = %q, want ok", receipt.Status)
	}
	if receipt.Subject != "synthetic-service" {
		t.Fatalf("subject = %q", receipt.Subject)
	}
	if receipt.CheckedSurfaces[0] != "schema" || receipt.NonClaims[0] != "does not claim live production readiness" {
		t.Fatalf("receipt did not copy report slices: %+v", receipt)
	}
	if len(receipt.Commands) != 1 || receipt.Commands[0] != "ocsctl conformance <module-package.json>" {
		t.Fatalf("unexpected evidence command: %v", receipt.Commands)
	}
	if _, err := time.Parse(time.RFC3339, receipt.GeneratedAt); err != nil {
		t.Fatalf("generatedAt is not RFC3339: %q: %v", receipt.GeneratedAt, err)
	}

	report.Passed = false
	if failed := ocsv3.BuildEvidenceReceipt(report); failed.Status != "failed" {
		t.Fatalf("failed report receipt status = %q", failed.Status)
	}
}

func removeLifecycleAction(actions []ocsv3.LifecycleAction, name string) []ocsv3.LifecycleAction {
	out := make([]ocsv3.LifecycleAction, 0, len(actions))
	for _, action := range actions {
		if action.Name != name {
			out = append(out, action)
		}
	}
	return out
}

func hasProblem(problems []ocsv3.ConformanceProblem, field string) bool {
	for _, problem := range problems {
		if problem.Field == field {
			return true
		}
	}
	return false
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
