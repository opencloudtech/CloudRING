// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package httpsecurity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const canonicalTestURL = "https://public.example.test/console/%2Fready?probe=one&mode=two"

func TestAuditPassesCanaryAndSteadyBrowserAndAPIContracts(t *testing.T) {
	tests := []struct {
		name    string
		mode    Mode
		surface Surface
	}{
		{name: "canary browser", mode: ModeCanary, surface: SurfaceBrowser},
		{name: "canary API", mode: ModeCanary, surface: SurfaceAPI},
		{name: "steady browser", mode: ModeSteady, surface: SurfaceBrowser},
		{name: "steady API", mode: ModeSteady, surface: SurfaceAPI},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validFixture(test.mode, test.surface)
			transport := &fixtureTransport{fixture: fixture}
			report, err := Audit(context.Background(), &http.Client{Transport: transport}, Target{
				ID:      "public-surface",
				URL:     canonicalTestURL,
				Surface: test.surface,
			}, test.mode)
			if err != nil {
				t.Fatalf("audit: %v", err)
			}
			if !report.Passed {
				t.Fatalf("audit blocked: %v", failedRuleIDs(report))
			}
			for _, rule := range report.Rules {
				if !rule.Passed {
					t.Fatalf("rule %q did not pass", rule.ID)
				}
			}
			requests := transport.recordedRequests()
			if len(requests) != 2 {
				t.Fatalf("request count = %d, want 2 (redirects must not be followed)", len(requests))
			}
			if requests[0].scheme != "http" || requests[1].scheme != "https" {
				t.Fatalf("request schemes = %q, %q", requests[0].scheme, requests[1].scheme)
			}
			for _, request := range requests {
				if request.method != http.MethodGet || request.host != "public.example.test" || request.path != "/console/%2Fready" || request.query != "probe=one&mode=two" {
					t.Fatalf("request did not preserve the canonical target: %+v", request)
				}
				if request.cookie != "" {
					t.Fatal("probe transmitted a cookie")
				}
			}
			if fixture.redirectBody.reads != 0 || fixture.secureBody.reads != 0 {
				t.Fatal("audit inspected a response body")
			}
			if !fixture.redirectBody.closed || !fixture.secureBody.closed {
				t.Fatal("audit did not close both response bodies")
			}
		})
	}
}

func TestAuditFailsClosedOnRedirectAndTLSViolations(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*responseFixture)
		failedRule string
	}{
		{
			name: "temporary redirect in steady mode",
			mutate: func(f *responseFixture) {
				f.redirectStatus = http.StatusTemporaryRedirect
			},
			failedRule: "redirect.status",
		},
		{
			name: "relative redirect",
			mutate: func(f *responseFixture) {
				f.redirectHeader.Set("Location", "/console/%2Fready?probe=one&mode=two")
			},
			failedRule: "redirect.location.absolute",
		},
		{
			name: "cross-authority redirect",
			mutate: func(f *responseFixture) {
				f.redirectHeader.Set("Location", "https://other.example.test/console/%2Fready?probe=one&mode=two")
			},
			failedRule: "redirect.location.same-authority",
		},
		{
			name: "redirect remains cleartext",
			mutate: func(f *responseFixture) {
				f.redirectHeader.Set("Location", "http://public.example.test/console/%2Fready?probe=one&mode=two")
			},
			failedRule: "redirect.location.https",
		},
		{
			name: "changed explicit port",
			mutate: func(f *responseFixture) {
				f.redirectHeader.Set("Location", "https://public.example.test:443/console/%2Fready?probe=one&mode=two")
			},
			failedRule: "redirect.location.port-preserved",
		},
		{
			name: "changed path",
			mutate: func(f *responseFixture) {
				f.redirectHeader.Set("Location", "https://public.example.test/changed?probe=one&mode=two")
			},
			failedRule: "redirect.location.path-preserved",
		},
		{
			name: "changed query",
			mutate: func(f *responseFixture) {
				f.redirectHeader.Set("Location", "https://public.example.test/console/%2Fready?mode=two&probe=one")
			},
			failedRule: "redirect.location.query-preserved",
		},
		{
			name: "redirect fragment",
			mutate: func(f *responseFixture) {
				f.redirectHeader.Set("Location", canonicalTestURL+"#unexpected")
			},
			failedRule: "redirect.location.fragment-free",
		},
		{
			name: "secure endpoint redirects",
			mutate: func(f *responseFixture) {
				f.secureStatus = http.StatusTemporaryRedirect
			},
			failedRule: "secure.status.success",
		},
		{
			name: "no TLS state",
			mutate: func(f *responseFixture) {
				f.tlsState = nil
			},
			failedRule: "tls.present",
		},
		{
			name: "unfinished TLS handshake",
			mutate: func(f *responseFixture) {
				f.tlsState.HandshakeComplete = false
			},
			failedRule: "tls.handshake-complete",
		},
		{
			name: "obsolete TLS",
			mutate: func(f *responseFixture) {
				f.tlsState.Version = tls.VersionTLS11
			},
			failedRule: "tls.version-1.2-or-newer",
		},
		{
			name: "unverified certificate chain",
			mutate: func(f *responseFixture) {
				f.tlsState.VerifiedChains = nil
			},
			failedRule: "tls.chain-verified",
		},
		{
			name: "peer certificate is for another hostname",
			mutate: func(f *responseFixture) {
				f.tlsState.PeerCertificates = []*x509.Certificate{{DNSNames: []string{"other.example.test"}}}
			},
			failedRule: "tls.chain-verified",
		},
		{
			name: "verified chain is for another hostname",
			mutate: func(f *responseFixture) {
				f.tlsState.VerifiedChains = [][]*x509.Certificate{{{DNSNames: []string{"other.example.test"}}}}
			},
			failedRule: "tls.chain-verified",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validFixture(ModeSteady, SurfaceBrowser)
			test.mutate(fixture)
			report := auditFixture(t, fixture, ModeSteady, SurfaceBrowser)
			assertRuleFailed(t, report, test.failedRule)
		})
	}
}

func TestAuditEnforcesExactCanaryAndSafeSteadyHSTS(t *testing.T) {
	tests := []struct {
		name       string
		mode       Mode
		value      string
		failedRule string
	}{
		{name: "canary is not shorter", mode: ModeCanary, value: "max-age=299", failedRule: "hsts.max-age"},
		{name: "canary is not longer", mode: ModeCanary, value: "max-age=301", failedRule: "hsts.max-age"},
		{name: "steady is at least one year", mode: ModeSteady, value: "max-age=31535999", failedRule: "hsts.max-age"},
		{name: "canary excludes subdomains", mode: ModeCanary, value: "max-age=300; includeSubDomains", failedRule: "hsts.include-subdomains.absent"},
		{name: "canary excludes preload", mode: ModeCanary, value: "max-age=300; preload", failedRule: "hsts.preload.absent"},
		{name: "steady excludes subdomains before domain audit", mode: ModeSteady, value: "max-age=31536000; includeSubDomains", failedRule: "hsts.include-subdomains.absent"},
		{name: "steady excludes preload before domain audit", mode: ModeSteady, value: "max-age=31536000; preload", failedRule: "hsts.preload.absent"},
		{name: "duplicate directive is invalid", mode: ModeCanary, value: "max-age=300; max-age=300", failedRule: "hsts.syntax"},
		{name: "quoted max age is invalid", mode: ModeCanary, value: "max-age=\"300\"", failedRule: "hsts.syntax"},
		{name: "unknown valued directive is invalid", mode: ModeCanary, value: "max-age=300; extension=value", failedRule: "hsts.syntax"},
		{name: "unknown valueless directive is invalid", mode: ModeCanary, value: "max-age=300; extension", failedRule: "hsts.syntax"},
		{name: "flag value is invalid", mode: ModeCanary, value: "max-age=300; preload=false", failedRule: "hsts.syntax"},
		{name: "nonbreaking space is invalid", mode: ModeCanary, value: "max-age=\u00a0300", failedRule: "hsts.syntax"},
		{name: "zero is not a canary", mode: ModeCanary, value: "max-age=0", failedRule: "hsts.max-age"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validFixture(test.mode, SurfaceBrowser)
			fixture.secureHeader.Set("Strict-Transport-Security", test.value)
			report := auditFixture(t, fixture, test.mode, SurfaceBrowser)
			assertRuleFailed(t, report, test.failedRule)
		})
	}
}

func TestAuditEnforcesBrowserAndAPISecurityHeaderPolicies(t *testing.T) {
	tests := []struct {
		name       string
		surface    Surface
		mutate     func(http.Header)
		failedRule string
	}{
		{name: "browser default source is bounded", surface: SurfaceBrowser, mutate: setHeader("Content-Security-Policy", "default-src *; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"), failedRule: "csp.default-src"},
		{name: "API default source denies all", surface: SurfaceAPI, mutate: setHeader("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; sandbox"), failedRule: "csp.default-src"},
		{name: "API is sandboxed", surface: SurfaceAPI, mutate: setHeader("Content-Security-Policy", "default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"), failedRule: "csp.api.sandbox"},
		{name: "objects are denied", surface: SurfaceBrowser, mutate: setHeader("Content-Security-Policy", "default-src 'self'; object-src 'self'; base-uri 'none'; frame-ancestors 'none'"), failedRule: "csp.object-src-none"},
		{name: "base URI is denied", surface: SurfaceBrowser, mutate: setHeader("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"), failedRule: "csp.base-uri-none"},
		{name: "frame ancestors are denied", surface: SurfaceBrowser, mutate: setHeader("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'"), failedRule: "csp.frame-ancestors-none"},
		{name: "CSP duplicate directive is invalid", surface: SurfaceBrowser, mutate: setHeader("Content-Security-Policy", "default-src 'self'; default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"), failedRule: "csp.syntax"},
		{name: "browser scripts reject unsafe inline", surface: SurfaceBrowser, mutate: setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"), failedRule: "csp.script.no-unsafe-inline"},
		{name: "browser scripts reject unsafe eval", surface: SurfaceBrowser, mutate: setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"), failedRule: "csp.script.no-unsafe-eval"},
		{name: "browser script element override rejects unsafe inline", surface: SurfaceBrowser, mutate: setHeader("Content-Security-Policy", "default-src 'self'; script-src-elem 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"), failedRule: "csp.script.no-unsafe-inline"},
		{name: "frame option denies", surface: SurfaceBrowser, mutate: setHeader("X-Frame-Options", "SAMEORIGIN"), failedRule: "x-frame-options.deny"},
		{name: "content type is not sniffed", surface: SurfaceBrowser, mutate: setHeader("X-Content-Type-Options", "sniff"), failedRule: "x-content-type-options.nosniff"},
		{name: "referrer is suppressed", surface: SurfaceBrowser, mutate: setHeader("Referrer-Policy", "strict-origin"), failedRule: "referrer-policy.no-referrer"},
		{name: "camera is disabled", surface: SurfaceBrowser, mutate: setHeader("Permissions-Policy", "camera=(self), microphone=(), geolocation=(), payment=(), usb=()"), failedRule: "permissions-policy.camera-disabled"},
		{name: "microphone is disabled", surface: SurfaceBrowser, mutate: setHeader("Permissions-Policy", "camera=(), microphone=(self), geolocation=(), payment=(), usb=()"), failedRule: "permissions-policy.microphone-disabled"},
		{name: "geolocation is disabled", surface: SurfaceBrowser, mutate: setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(self), payment=(), usb=()"), failedRule: "permissions-policy.geolocation-disabled"},
		{name: "payment is disabled", surface: SurfaceBrowser, mutate: setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(self), usb=()"), failedRule: "permissions-policy.payment-disabled"},
		{name: "USB is disabled", surface: SurfaceBrowser, mutate: setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(self)"), failedRule: "permissions-policy.usb-disabled"},
		{name: "permissions duplicates are invalid", surface: SurfaceBrowser, mutate: setHeader("Permissions-Policy", "camera=(), camera=(), microphone=(), geolocation=(), payment=(), usb=()"), failedRule: "permissions-policy.syntax"},
		{name: "permissions unknown member is invalid", surface: SurfaceBrowser, mutate: setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=()"), failedRule: "permissions-policy.syntax"},
		{name: "permissions malformed extra member is invalid", surface: SurfaceBrowser, mutate: setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=("), failedRule: "permissions-policy.syntax"},
		{name: "permissions uppercase key is invalid", surface: SurfaceBrowser, mutate: setHeader("Permissions-Policy", "CAMERA=(), microphone=(), geolocation=(), payment=(), usb=()"), failedRule: "permissions-policy.syntax"},
		{name: "permissions quoted allowlist is invalid", surface: SurfaceBrowser, mutate: setHeader("Permissions-Policy", "camera=\"()\", microphone=(), geolocation=(), payment=(), usb=()"), failedRule: "permissions-policy.syntax"},
		{name: "permissions parameter is invalid", surface: SurfaceBrowser, mutate: setHeader("Permissions-Policy", "camera=();enabled=?1, microphone=(), geolocation=(), payment=(), usb=()"), failedRule: "permissions-policy.syntax"},
		{name: "non-ASCII nosniff lookalike is invalid", surface: SurfaceBrowser, mutate: setHeader("X-Content-Type-Options", "noſniff"), failedRule: "x-content-type-options.nosniff"},
		{name: "non-ASCII same-origin lookalike is invalid", surface: SurfaceBrowser, mutate: setHeader("Cross-Origin-Opener-Policy", "ſame-origin"), failedRule: "coop.same-origin"},
		{name: "control byte in security header is invalid", surface: SurfaceBrowser, mutate: setHeader("X-Frame-Options", "DENY\x00"), failedRule: "header.x-frame-options.no-conflict"},
		{name: "opener is isolated", surface: SurfaceBrowser, mutate: setHeader("Cross-Origin-Opener-Policy", "unsafe-none"), failedRule: "coop.same-origin"},
		{name: "resources are same origin", surface: SurfaceBrowser, mutate: setHeader("Cross-Origin-Resource-Policy", "cross-origin"), failedRule: "corp.same-origin"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validFixture(ModeCanary, test.surface)
			test.mutate(fixture.secureHeader)
			report := auditFixture(t, fixture, ModeCanary, test.surface)
			assertRuleFailed(t, report, test.failedRule)
		})
	}
}

func TestAuditRequiresEverySecurityHeader(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		failedRule string
		redirect   bool
	}{
		{name: "Location", headerName: "Location", failedRule: "redirect.location.present", redirect: true},
		{name: "HSTS", headerName: "Strict-Transport-Security", failedRule: "header.hsts.present"},
		{name: "CSP", headerName: "Content-Security-Policy", failedRule: "header.csp.present"},
		{name: "frame", headerName: "X-Frame-Options", failedRule: "header.x-frame-options.present"},
		{name: "nosniff", headerName: "X-Content-Type-Options", failedRule: "header.x-content-type-options.present"},
		{name: "referrer", headerName: "Referrer-Policy", failedRule: "header.referrer-policy.present"},
		{name: "permissions", headerName: "Permissions-Policy", failedRule: "header.permissions-policy.present"},
		{name: "COOP", headerName: "Cross-Origin-Opener-Policy", failedRule: "header.coop.present"},
		{name: "CORP", headerName: "Cross-Origin-Resource-Policy", failedRule: "header.corp.present"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validFixture(ModeCanary, SurfaceBrowser)
			header := fixture.secureHeader
			if test.redirect {
				header = fixture.redirectHeader
			}
			header.Del(test.headerName)
			report := auditFixture(t, fixture, ModeCanary, SurfaceBrowser)
			assertRuleFailed(t, report, test.failedRule)
		})
	}
}

func TestAuditAcceptsOnlyIdenticalDuplicateHeaderValues(t *testing.T) {
	fixture := validFixture(ModeCanary, SurfaceBrowser)
	fixture.redirectHeader.Add("Location", canonicalTestURL)
	for _, name := range []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Resource-Policy",
	} {
		fixture.secureHeader.Add(name, fixture.secureHeader.Get(name))
	}
	transport := &fixtureTransport{fixture: fixture}
	report, err := Audit(context.Background(), &http.Client{Transport: transport}, Target{
		ID:      "duplicate-test",
		URL:     canonicalTestURL,
		Surface: SurfaceBrowser,
	}, ModeCanary)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !report.Passed {
		t.Fatalf("identical duplicate values were treated as conflicting: %v", failedRuleIDs(report))
	}
}

func TestAuditFailsClosedOnConflictingDuplicateHeaders(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		value      string
		failedRule string
		redirect   bool
	}{
		{name: "Location", headerName: "Location", value: "https://other.example.test/", failedRule: "redirect.location.no-conflict", redirect: true},
		{name: "HSTS", headerName: "Strict-Transport-Security", value: "max-age=301", failedRule: "header.hsts.no-conflict"},
		{name: "CSP", headerName: "Content-Security-Policy", value: "default-src *", failedRule: "header.csp.no-conflict"},
		{name: "frame", headerName: "X-Frame-Options", value: "SAMEORIGIN", failedRule: "header.x-frame-options.no-conflict"},
		{name: "nosniff", headerName: "X-Content-Type-Options", value: "sniff", failedRule: "header.x-content-type-options.no-conflict"},
		{name: "referrer", headerName: "Referrer-Policy", value: "origin", failedRule: "header.referrer-policy.no-conflict"},
		{name: "permissions", headerName: "Permissions-Policy", value: "camera=(self)", failedRule: "header.permissions-policy.no-conflict"},
		{name: "COOP", headerName: "Cross-Origin-Opener-Policy", value: "unsafe-none", failedRule: "header.coop.no-conflict"},
		{name: "CORP", headerName: "Cross-Origin-Resource-Policy", value: "cross-origin", failedRule: "header.corp.no-conflict"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validFixture(ModeCanary, SurfaceBrowser)
			header := fixture.secureHeader
			if test.redirect {
				header = fixture.redirectHeader
			}
			header.Add(test.headerName, test.value)
			report := auditFixture(t, fixture, ModeCanary, SurfaceBrowser)
			assertRuleFailed(t, report, test.failedRule)
		})
	}
}

func TestAuditReportAndErrorsDoNotExposeInputsOrResponses(t *testing.T) {
	privateMarker := "opaque-" + "response-marker"
	privateURL := "https://sensitive.example.test/private/" + privateMarker + "?opaque=" + privateMarker
	fixture := validFixture(ModeCanary, SurfaceBrowser)
	fixture.redirectHeader.Set("Location", "https://sensitive.example.test/private/changed?opaque="+privateMarker)
	fixture.secureHeader.Set("Cross-Origin-Resource-Policy", privateMarker)
	fixture.secureBody.payload = privateMarker
	transport := &fixtureTransport{fixture: fixture}
	report, err := Audit(context.Background(), &http.Client{Transport: transport}, Target{
		ID:      "sanitized-target",
		URL:     privateURL,
		Surface: SurfaceBrowser,
	}, ModeCanary)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encode report: %v", err)
	}
	assertSanitizedReportShape(t, encoded)
	for _, forbidden := range []string{privateURL, privateMarker, "sensitive.example.test", "private/changed"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("report exposes private input or response content %q: %s", forbidden, encoded)
		}
	}
	if fixture.secureBody.reads != 0 {
		t.Fatal("audit read the private response body")
	}

	transport.failure = errors.New(privateMarker)
	failedReport, err := Audit(context.Background(), &http.Client{Transport: transport}, Target{
		ID:      "sanitized-target",
		URL:     privateURL,
		Surface: SurfaceBrowser,
	}, ModeCanary)
	if err != nil {
		t.Fatalf("network failure must become rule results, got %v", err)
	}
	failedJSON, err := json.Marshal(failedReport)
	if err != nil {
		t.Fatalf("encode failure report: %v", err)
	}
	if strings.Contains(string(failedJSON), privateMarker) || strings.Contains(string(failedJSON), privateURL) {
		t.Fatalf("network failure report leaks input: %s", failedJSON)
	}

	_, err = Audit(context.Background(), nil, Target{ID: "invalid/id", URL: privateURL, Surface: SurfaceBrowser}, ModeCanary)
	if !errors.Is(err, ErrInvalidConfiguration) || strings.Contains(err.Error(), privateMarker) || strings.Contains(err.Error(), privateURL) {
		t.Fatalf("invalid configuration error is not opaque: %v", err)
	}
}

func assertSanitizedReportShape(t *testing.T, encoded []byte) {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatalf("decode report shape: %v", err)
	}
	allowedTopLevel := map[string]bool{
		"schema_version": true,
		"target_id":      true,
		"mode":           true,
		"surface":        true,
		"passed":         true,
		"rules":          true,
	}
	for key := range object {
		if !allowedTopLevel[key] {
			t.Fatalf("report has a non-sanitized top-level field %q", key)
		}
	}
	rules, ok := object["rules"].([]any)
	if !ok {
		t.Fatalf("report rules have unexpected shape: %T", object["rules"])
	}
	for _, rawRule := range rules {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			t.Fatalf("report rule has unexpected shape: %T", rawRule)
		}
		for key := range rule {
			if key != "id" && key != "passed" {
				t.Fatalf("report rule has a non-sanitized field %q", key)
			}
		}
	}
}

func TestAuditRejectsUnsafeTargetConfigurationBeforeNetworkAccess(t *testing.T) {
	tests := []Target{
		{ID: "unsafe/id", URL: canonicalTestURL, Surface: SurfaceBrowser},
		{ID: "safe", URL: "http://public.example.test/", Surface: SurfaceBrowser},
		{ID: "safe", URL: "https://user@public.example.test/", Surface: SurfaceBrowser},
		{ID: "safe", URL: "https://public.example.test/#fragment", Surface: SurfaceBrowser},
		{ID: "safe", URL: "relative/path", Surface: SurfaceBrowser},
		{ID: "safe", URL: canonicalTestURL, Surface: "unknown"},
	}
	for index, target := range tests {
		transport := &fixtureTransport{fixture: validFixture(ModeCanary, SurfaceBrowser)}
		if _, err := Audit(context.Background(), &http.Client{Transport: transport}, target, ModeCanary); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("case %d: got error %v", index, err)
		}
		if got := len(transport.recordedRequests()); got != 0 {
			t.Fatalf("case %d made %d request(s) before rejecting configuration", index, got)
		}
	}
}

func auditFixture(t *testing.T, fixture *responseFixture, mode Mode, surface Surface) Report {
	t.Helper()
	report, err := Audit(context.Background(), &http.Client{Transport: &fixtureTransport{fixture: fixture}}, Target{
		ID:      "test-target",
		URL:     canonicalTestURL,
		Surface: surface,
	}, mode)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if report.Passed {
		t.Fatal("audit unexpectedly passed")
	}
	return report
}

func assertRuleFailed(t *testing.T, report Report, id string) {
	t.Helper()
	for _, rule := range report.Rules {
		if rule.ID == id {
			if rule.Passed {
				t.Fatalf("rule %q unexpectedly passed; failed rules: %v", id, failedRuleIDs(report))
			}
			return
		}
	}
	t.Fatalf("rule %q is absent from report", id)
}

func failedRuleIDs(report Report) []string {
	var failed []string
	for _, rule := range report.Rules {
		if !rule.Passed {
			failed = append(failed, rule.ID)
		}
	}
	return failed
}

func setHeader(name, value string) func(http.Header) {
	return func(header http.Header) {
		header.Set(name, value)
	}
}

type responseFixture struct {
	redirectStatus int
	redirectHeader http.Header
	redirectBody   *trackingBody
	secureStatus   int
	secureHeader   http.Header
	secureBody     *trackingBody
	tlsState       *tls.ConnectionState
}

func validFixture(mode Mode, surface Surface) *responseFixture {
	redirectStatus := http.StatusTemporaryRedirect
	if mode == ModeSteady {
		redirectStatus = http.StatusPermanentRedirect
	}
	secureHeader := http.Header{}
	hsts := "max-age=300"
	if mode == ModeSteady {
		hsts = "max-age=31536000"
	}
	secureHeader.Set("Strict-Transport-Security", hsts)
	csp := "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
	if surface == SurfaceAPI {
		csp = "default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; sandbox"
	}
	secureHeader.Set("Content-Security-Policy", csp)
	secureHeader.Set("X-Frame-Options", "DENY")
	secureHeader.Set("X-Content-Type-Options", "nosniff")
	secureHeader.Set("Referrer-Policy", "no-referrer")
	secureHeader.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	secureHeader.Set("Cross-Origin-Opener-Policy", "same-origin")
	secureHeader.Set("Cross-Origin-Resource-Policy", "same-origin")
	certificate := &x509.Certificate{DNSNames: []string{"public.example.test"}}
	return &responseFixture{
		redirectStatus: redirectStatus,
		redirectHeader: http.Header{"Location": []string{canonicalTestURL}},
		redirectBody:   &trackingBody{},
		secureStatus:   http.StatusOK,
		secureHeader:   secureHeader,
		secureBody:     &trackingBody{},
		tlsState: &tls.ConnectionState{
			Version:           tls.VersionTLS13,
			HandshakeComplete: true,
			PeerCertificates:  []*x509.Certificate{certificate},
			VerifiedChains:    [][]*x509.Certificate{{certificate}},
		},
	}
}

type recordedRequest struct {
	method string
	scheme string
	host   string
	path   string
	query  string
	cookie string
}

type fixtureTransport struct {
	mu       sync.Mutex
	fixture  *responseFixture
	failure  error
	requests []recordedRequest
}

func (t *fixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.requests = append(t.requests, recordedRequest{
		method: request.Method,
		scheme: request.URL.Scheme,
		host:   request.URL.Host,
		path:   request.URL.EscapedPath(),
		query:  request.URL.RawQuery,
		cookie: request.Header.Get("Cookie"),
	})
	failure := t.failure
	t.mu.Unlock()
	if failure != nil {
		return nil, failure
	}
	if request.URL.Scheme == "http" {
		return &http.Response{
			StatusCode: t.fixture.redirectStatus,
			Header:     t.fixture.redirectHeader.Clone(),
			Body:       t.fixture.redirectBody,
			Request:    request,
		}, nil
	}
	return &http.Response{
		StatusCode: t.fixture.secureStatus,
		Header:     t.fixture.secureHeader.Clone(),
		Body:       t.fixture.secureBody,
		Request:    request,
		TLS:        cloneTLSState(t.fixture.tlsState),
	}, nil
}

func (t *fixtureTransport) recordedRequests() []recordedRequest {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]recordedRequest{}, t.requests...)
}

func cloneTLSState(input *tls.ConnectionState) *tls.ConnectionState {
	if input == nil {
		return nil
	}
	cloned := *input
	cloned.PeerCertificates = append([]*x509.Certificate{}, input.PeerCertificates...)
	cloned.VerifiedChains = make([][]*x509.Certificate, len(input.VerifiedChains))
	for i := range input.VerifiedChains {
		cloned.VerifiedChains[i] = append([]*x509.Certificate{}, input.VerifiedChains[i]...)
	}
	return &cloned
}

type trackingBody struct {
	payload string
	reads   int
	closed  bool
}

func (b *trackingBody) Read(buffer []byte) (int, error) {
	b.reads++
	if b.payload == "" {
		return 0, io.EOF
	}
	n := copy(buffer, b.payload)
	b.payload = b.payload[n:]
	return n, nil
}

func (b *trackingBody) Close() error {
	b.closed = true
	return nil
}

type cookieJar struct {
	cookies []*http.Cookie
}

func (j cookieJar) SetCookies(_ *url.URL, _ []*http.Cookie) {}

func (j cookieJar) Cookies(_ *url.URL) []*http.Cookie {
	return append([]*http.Cookie{}, j.cookies...)
}

func TestCloneProbeClientDropsCookieJarAndOverridesRedirectPolicy(t *testing.T) {
	originalRedirectCalls := 0
	original := &http.Client{
		Jar: cookieJar{cookies: []*http.Cookie{{Name: "session", Value: "opaque", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}}},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			originalRedirectCalls++
			return nil
		},
	}
	cloned := cloneProbeClient(original)
	if cloned.Jar != nil {
		t.Fatal("probe client retained the caller's cookie jar")
	}
	if err := cloned.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect override = %v", err)
	}
	if originalRedirectCalls != 0 {
		t.Fatal("probe invoked the caller's redirect policy")
	}
	if original.Jar == nil || reflect.ValueOf(original.CheckRedirect).IsNil() {
		t.Fatal("probe mutated the caller's client")
	}
}
