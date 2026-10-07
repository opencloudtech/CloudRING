// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/httpsecurity"
)

const cliTestURL = "https://public.example.test/ready?probe=cli"

func TestRunExitSemanticsAndSanitizedOutput(t *testing.T) {
	t.Run("pass is zero", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := run(context.Background(), validCLIArgs(cliTestURL), validCLIClient(cliTestURL), &stdout, &stderr)
		if code != exitPassed {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
		var report httpsecurity.Report
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatalf("decode report: %v", err)
		}
		if !report.Passed || report.TargetID != "public-check" || stderr.Len() != 0 {
			t.Fatalf("unexpected output: report=%+v stderr=%q", report, stderr.String())
		}
	})

	t.Run("policy violation is two and redacted", func(t *testing.T) {
		privateMarker := "opaque-" + "response-value"
		privateURL := "https://sensitive.example.test/private?opaque=" + privateMarker
		transport := validCLITransport(privateURL)
		transport.secureHeader.Set("Cross-Origin-Resource-Policy", privateMarker)
		transport.body = privateMarker
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := run(context.Background(), validCLIArgs(privateURL), &http.Client{Transport: transport}, &stdout, &stderr)
		if code != exitBlocked {
			t.Fatalf("exit code = %d, want %d", code, exitBlocked)
		}
		combined := stdout.String() + stderr.String()
		for _, forbidden := range []string{privateURL, privateMarker, "sensitive.example.test", "private?"} {
			if strings.Contains(combined, forbidden) {
				t.Fatalf("CLI output exposes %q: %s", forbidden, combined)
			}
		}
		if !strings.Contains(stdout.String(), "corp.same-origin") || !strings.Contains(stderr.String(), "audit blocked") {
			t.Fatalf("blocked output lacks sanitized result: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	})

	t.Run("network failure is two and redacted", func(t *testing.T) {
		privateMarker := "opaque-" + "transport-value"
		transport := validCLITransport(cliTestURL)
		transport.failure = errors.New(privateMarker)
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := run(context.Background(), validCLIArgs(cliTestURL), &http.Client{Transport: transport}, &stdout, &stderr)
		if code != exitBlocked {
			t.Fatalf("exit code = %d, want %d", code, exitBlocked)
		}
		if strings.Contains(stdout.String()+stderr.String(), privateMarker) || strings.Contains(stdout.String()+stderr.String(), cliTestURL) {
			t.Fatalf("network error leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	})

	t.Run("usage or invalid configuration is one", func(t *testing.T) {
		privateURL := "http://sensitive.example.test/private"
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := run(context.Background(), validCLIArgs(privateURL), validCLIClient(cliTestURL), &stdout, &stderr)
		if code != exitUsage {
			t.Fatalf("exit code = %d, want %d", code, exitUsage)
		}
		if stdout.Len() != 0 || strings.Contains(stderr.String(), privateURL) || strings.Contains(stderr.String(), "sensitive.example.test") {
			t.Fatalf("invalid configuration was reflected: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	})
}

func TestParseArgsRequiresOneExplicitSafeContract(t *testing.T) {
	target, mode, err := parseArgs(validCLIArgs(cliTestURL))
	if err != nil {
		t.Fatalf("parse valid arguments: %v", err)
	}
	if target.ID != "public-check" || target.URL != cliTestURL || target.Surface != httpsecurity.SurfaceBrowser || mode != httpsecurity.ModeCanary {
		t.Fatalf("unexpected parsed contract: target=%+v mode=%q", target, mode)
	}
	invalid := [][]string{
		nil,
		{"inspect"},
		{"check"},
		{"check", "--target-id", "public-check", "--url", cliTestURL, "--mode", "unknown", "--surface", "browser"},
		{"check", "--target-id", "public-check", "--url", cliTestURL, "--mode", "canary", "--surface", "unknown"},
		append(validCLIArgs(cliTestURL), "unexpected"),
	}
	for index, args := range invalid {
		if _, _, err := parseArgs(args); err == nil || err.Error() != usageError().Error() {
			t.Fatalf("case %d: expected opaque usage error, got %v", index, err)
		}
	}
}

func validCLIArgs(targetURL string) []string {
	return []string{
		"check",
		"--target-id", "public-check",
		"--url", targetURL,
		"--mode", "canary",
		"--surface", "browser",
	}
}

func validCLIClient(targetURL string) *http.Client {
	return &http.Client{Transport: validCLITransport(targetURL)}
}

func validCLITransport(targetURL string) *cliTransport {
	header := http.Header{}
	header.Set("Strict-Transport-Security", "max-age=300")
	header.Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	header.Set("X-Frame-Options", "DENY")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	return &cliTransport{targetURL: targetURL, secureHeader: header}
}

type cliTransport struct {
	targetURL    string
	secureHeader http.Header
	body         string
	failure      error
}

func (t *cliTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.failure != nil {
		return nil, t.failure
	}
	if request.URL.Scheme == "http" {
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": []string{t.targetURL}},
			Body:       io.NopCloser(strings.NewReader(t.body)),
			Request:    request,
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     t.secureHeader.Clone(),
		Body:       io.NopCloser(strings.NewReader(t.body)),
		Request:    request,
		TLS: &tls.ConnectionState{
			Version:           tls.VersionTLS13,
			HandshakeComplete: true,
			PeerCertificates:  []*x509.Certificate{{DNSNames: []string{request.URL.Hostname()}}},
			VerifiedChains:    [][]*x509.Certificate{{{DNSNames: []string{request.URL.Hostname()}}}},
		},
	}, nil
}
