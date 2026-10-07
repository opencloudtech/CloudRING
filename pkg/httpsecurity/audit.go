// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package httpsecurity

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
)

const maxTargetURLBytes = 4_096

var commonRuleIDs = []string{
	"redirect.request",
	"redirect.status",
	"redirect.location.present",
	"redirect.location.no-conflict",
	"redirect.location.absolute",
	"redirect.location.https",
	"redirect.location.host-preserved",
	"redirect.location.port-preserved",
	"redirect.location.same-authority",
	"redirect.location.path-preserved",
	"redirect.location.query-preserved",
	"redirect.location.fragment-free",
	"secure.request",
	"secure.status.success",
	"tls.present",
	"tls.handshake-complete",
	"tls.version-1.2-or-newer",
	"tls.chain-verified",
	"header.hsts.present",
	"header.hsts.no-conflict",
	"hsts.syntax",
	"hsts.max-age",
	"hsts.include-subdomains.absent",
	"hsts.preload.absent",
	"header.csp.present",
	"header.csp.no-conflict",
	"csp.syntax",
	"csp.default-src",
	"csp.object-src-none",
	"csp.base-uri-none",
	"csp.frame-ancestors-none",
	"header.x-frame-options.present",
	"header.x-frame-options.no-conflict",
	"x-frame-options.deny",
	"header.x-content-type-options.present",
	"header.x-content-type-options.no-conflict",
	"x-content-type-options.nosniff",
	"header.referrer-policy.present",
	"header.referrer-policy.no-conflict",
	"referrer-policy.no-referrer",
	"header.permissions-policy.present",
	"header.permissions-policy.no-conflict",
	"permissions-policy.syntax",
	"permissions-policy.camera-disabled",
	"permissions-policy.microphone-disabled",
	"permissions-policy.geolocation-disabled",
	"permissions-policy.payment-disabled",
	"permissions-policy.usb-disabled",
	"header.coop.present",
	"header.coop.no-conflict",
	"coop.same-origin",
	"header.corp.present",
	"header.corp.no-conflict",
	"corp.same-origin",
}

// Audit performs two read-only GET requests: one over HTTP to inspect the
// redirect response without following it, then one directly over HTTPS to
// inspect TLS and response headers. The returned report is sanitized by
// construction.
func Audit(ctx context.Context, client *http.Client, target Target, mode Mode) (Report, error) {
	canonical, err := validateConfiguration(target, mode)
	if err != nil {
		return Report{}, err
	}
	ruleIDs := append([]string{}, commonRuleIDs...)
	if target.Surface == SurfaceAPI {
		ruleIDs = append(ruleIDs, "csp.api.sandbox")
	} else {
		ruleIDs = append(ruleIDs,
			"csp.script.no-unsafe-inline",
			"csp.script.no-unsafe-eval",
		)
	}
	report := newReport(target, mode, ruleIDs)

	probeClient := cloneProbeClient(client)
	checkRedirect(ctx, probeClient, canonical, mode, &report)
	checkSecure(ctx, probeClient, canonical, target.Surface, mode, &report)
	report.finalize()
	return report, nil
}

func validateConfiguration(target Target, mode Mode) (*url.URL, error) {
	if !targetIDPattern.MatchString(target.ID) || !mode.valid() || !target.Surface.valid() {
		return nil, ErrInvalidConfiguration
	}
	if target.URL == "" || len(target.URL) > maxTargetURLBytes || strings.ContainsRune(target.URL, '\x00') {
		return nil, ErrInvalidConfiguration
	}
	parsed, err := url.Parse(target.URL)
	if err != nil || parsed == nil {
		return nil, ErrInvalidConfiguration
	}
	if !parsed.IsAbs() || !strings.EqualFold(parsed.Scheme, "https") || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return nil, ErrInvalidConfiguration
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" {
		return nil, ErrInvalidConfiguration
	}
	parsed.Scheme = "https"
	return parsed, nil
}

func cloneProbeClient(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	cloned := *client
	cloned.Jar = nil
	cloned.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &cloned
}

func checkRedirect(ctx context.Context, client *http.Client, canonical *url.URL, mode Mode, report *Report) {
	cleartext := cloneURL(canonical)
	cleartext.Scheme = "http"
	response := doRequest(ctx, client, cleartext)
	if response == nil {
		return
	}
	defer response.Body.Close()
	report.setRule("redirect.request", true)

	expectedStatus := http.StatusTemporaryRedirect
	if mode == ModeSteady {
		expectedStatus = http.StatusPermanentRedirect
	}
	report.setRule("redirect.status", response.StatusCode == expectedStatus)

	locationValue, present, noConflict := uniqueHeader(response.Header, "Location")
	report.setRule("redirect.location.present", present)
	report.setRule("redirect.location.no-conflict", noConflict)
	if !present || !noConflict {
		return
	}
	location, err := url.Parse(locationValue)
	if err != nil || location == nil {
		return
	}
	absolute := location.IsAbs() && location.Opaque == "" && location.Host != "" && location.Hostname() != ""
	report.setRule("redirect.location.absolute", absolute)
	if !absolute {
		return
	}
	report.setRule("redirect.location.https", strings.EqualFold(location.Scheme, "https"))
	hostPreserved := strings.EqualFold(location.Hostname(), canonical.Hostname())
	portPreserved := location.Port() == canonical.Port()
	report.setRule("redirect.location.host-preserved", hostPreserved)
	report.setRule("redirect.location.port-preserved", portPreserved)
	report.setRule("redirect.location.same-authority", location.User == nil && hostPreserved && portPreserved)
	report.setRule("redirect.location.path-preserved", location.EscapedPath() == canonical.EscapedPath())
	report.setRule("redirect.location.query-preserved", location.RawQuery == canonical.RawQuery && location.ForceQuery == canonical.ForceQuery)
	report.setRule("redirect.location.fragment-free", location.Fragment == "" && location.RawFragment == "")
}

func checkSecure(ctx context.Context, client *http.Client, canonical *url.URL, surface Surface, mode Mode, report *Report) {
	response := doRequest(ctx, client, canonical)
	if response == nil {
		return
	}
	defer response.Body.Close()
	report.setRule("secure.request", true)
	report.setRule("secure.status.success", response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices)
	if response.TLS != nil {
		report.setRule("tls.present", true)
		report.setRule("tls.handshake-complete", response.TLS.HandshakeComplete)
		report.setRule("tls.version-1.2-or-newer", response.TLS.Version >= tls.VersionTLS12)
		report.setRule("tls.chain-verified", hasVerifiedTLSChain(response.TLS, canonical.Hostname()))
	}
	for id, passed := range evaluateHeaders(response.Header, surface, mode) {
		report.setRule(id, passed)
	}
}

func hasVerifiedTLSChain(state *tls.ConnectionState, hostname string) bool {
	if state == nil || hostname == "" || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return false
	}
	if err := state.PeerCertificates[0].VerifyHostname(hostname); err != nil {
		return false
	}
	for _, chain := range state.VerifiedChains {
		if len(chain) > 0 && chain[0].VerifyHostname(hostname) == nil {
			return true
		}
	}
	return false
}

func doRequest(ctx context.Context, client *http.Client, target *url.URL) *http.Response {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil
	}
	request.Header.Set("Accept", "*/*")
	request.Header.Set("User-Agent", "cloudring-httpcheck/1")
	response, err := client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil
	}
	if response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil
	}
	return response
}

func cloneURL(input *url.URL) *url.URL {
	cloned := *input
	return &cloned
}
