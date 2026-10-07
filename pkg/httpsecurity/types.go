// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

// Package httpsecurity provides a provider-neutral, read-only audit of the
// public HTTP transport and response-header boundary for CloudRING surfaces.
package httpsecurity

import (
	"errors"
	"regexp"
)

const (
	// CanaryMaxAgeSeconds is the exact HSTS lifetime installed while a hostname
	// is still in its reversible canary phase.
	CanaryMaxAgeSeconds uint64 = 300
	// SteadyMinAgeSeconds is the minimum HSTS lifetime after steady promotion.
	SteadyMinAgeSeconds uint64 = 31_536_000
)

// Mode selects the redirect and HSTS promotion policy.
type Mode string

const (
	ModeCanary Mode = "canary"
	ModeSteady Mode = "steady"
)

// Surface selects the response-header policy for an interactive browser or an
// API response.
type Surface string

const (
	SurfaceBrowser Surface = "browser"
	SurfaceAPI     Surface = "api"
)

// Target identifies one HTTPS surface. URL is input only and is deliberately
// absent from Report.
type Target struct {
	ID      string
	URL     string
	Surface Surface
}

// RuleResult exposes only a stable rule identifier and its result. It never
// contains a URL, response value, body, or transport error.
type RuleResult struct {
	ID     string `json:"id"`
	Passed bool   `json:"passed"`
}

// Report is safe to persist or print. TargetID is restricted to a small safe
// identifier alphabet before any network request is made.
type Report struct {
	SchemaVersion string       `json:"schema_version"`
	TargetID      string       `json:"target_id"`
	Mode          Mode         `json:"mode"`
	Surface       Surface      `json:"surface"`
	Passed        bool         `json:"passed"`
	Rules         []RuleResult `json:"rules"`
}

const reportSchemaVersion = "cloudring.httpsecurity/v1"

var targetIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ErrInvalidConfiguration is intentionally opaque so an invalid URL or target
// identifier cannot be reflected into logs.
var ErrInvalidConfiguration = errors.New("invalid HTTP security audit configuration")

func (m Mode) valid() bool {
	return m == ModeCanary || m == ModeSteady
}

func (s Surface) valid() bool {
	return s == SurfaceBrowser || s == SurfaceAPI
}

func newReport(target Target, mode Mode, ruleIDs []string) Report {
	rules := make([]RuleResult, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, RuleResult{ID: id})
	}
	return Report{
		SchemaVersion: reportSchemaVersion,
		TargetID:      target.ID,
		Mode:          mode,
		Surface:       target.Surface,
		Rules:         rules,
	}
}

func (r *Report) setRule(id string, passed bool) {
	for i := range r.Rules {
		if r.Rules[i].ID == id {
			r.Rules[i].Passed = passed
			return
		}
	}
	panic("httpsecurity: unknown internal rule identifier")
}

func (r *Report) finalize() {
	r.Passed = true
	for _, rule := range r.Rules {
		if !rule.Passed {
			r.Passed = false
			return
		}
	}
}
