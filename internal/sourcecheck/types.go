// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package sourcecheck

import "time"

type Scope string

const (
	ScopeFull    Scope = "full"
	ScopeTracked Scope = "tracked"
	ScopeChanged Scope = "changed"
	ScopePrePush Scope = "pre-push"
	ScopeFiles   Scope = "files"

	StatusApprove = "APPROVE"
	StatusBlocked = "BLOCKED"
)

type NonTextAllowance struct {
	Path   string
	SHA256 string
}

type PushUpdate struct {
	LocalRef  string
	LocalOID  string
	RemoteRef string
	RemoteOID string
}

type Options struct {
	Root              string
	Scope             Scope
	Files             []string
	Base              string
	Head              string
	RemoteName        string
	RemoteURLSHA256   string
	RemoteRefs        []string
	PushUpdates       []PushUpdate
	NonTextAllowances []NonTextAllowance
	RecurseGitlinks   bool
	OutputFormat      string
	ReportPath        string
	limits            *resourceLimits
}

type PathIdentity struct {
	Display   string `json:"display"`
	SHA256    string `json:"sha256"`
	Base64URL string `json:"base64url"`
}

type Finding struct {
	Rule          string `json:"rule"`
	Class         string `json:"class"`
	Path          string `json:"path"`
	PathSHA256    string `json:"pathSHA256"`
	PathBase64URL string `json:"pathBase64url"`
	Line          int    `json:"line,omitempty"`
	Column        int    `json:"column,omitempty"`
	SourceVariant string `json:"sourceVariant"`
	ContentSHA256 string `json:"contentSHA256"`
	Message       string `json:"message"`
}

type ScannedInput struct {
	Path          string `json:"path"`
	PathSHA256    string `json:"pathSHA256"`
	PathBase64URL string `json:"pathBase64url"`
	SourceVariant string `json:"sourceVariant"`
	Kind          string `json:"kind"`
	GitlinkState  string `json:"gitlinkState,omitempty"`
	SHA256        string `json:"sha256"`
}

type AllowanceReport struct {
	Path          string `json:"path"`
	PathSHA256    string `json:"pathSHA256"`
	PathBase64URL string `json:"pathBase64url"`
	SHA256        string `json:"sha256"`
	Consumed      bool   `json:"consumed"`
}

type Report struct {
	SchemaVersion     string            `json:"schemaVersion"`
	Command           string            `json:"command"`
	GeneratedAt       string            `json:"generatedAt"`
	Status            string            `json:"status"`
	Passed            bool              `json:"passed"`
	Scope             Scope             `json:"scope"`
	ScannedFiles      []PathIdentity    `json:"scannedFiles"`
	ScannedInputs     []ScannedInput    `json:"scannedInputs"`
	NonTextAllowances []AllowanceReport `json:"nonTextAllowances"`
	Findings          []Finding         `json:"findings"`
}

type scanInput struct {
	path          string
	variant       string
	data          []byte
	digest        string
	kind          string
	nonTextReason string
	gitlinkState  string
	gitlinkRoot   string
}

func newReport(scope Scope) Report {
	return Report{
		SchemaVersion:     "cloudring.source-safety/v2",
		Command:           "cloudring-sourcecheck scan",
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		Status:            StatusApprove,
		Passed:            true,
		Scope:             scope,
		ScannedFiles:      []PathIdentity{},
		ScannedInputs:     []ScannedInput{},
		NonTextAllowances: []AllowanceReport{},
		Findings:          []Finding{},
	}
}
