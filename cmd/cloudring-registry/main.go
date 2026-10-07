// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/opencloudtech/CloudRING/pkg/registry"
)

const (
	exitPassed  = 0
	exitUsage   = 1
	exitBlocked = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "validate" || args[1] == "" {
		fmt.Fprintln(stderr, "usage: cloudring-registry validate <registry-json>")
		return exitUsage
	}
	data, err := os.ReadFile(args[1]) // #nosec G703 G304 -- the operator explicitly selects a local contract file; output never reflects this path.
	if err != nil {
		fmt.Fprintln(stderr, "module registry unavailable")
		return exitUsage
	}
	parsed, err := registry.Parse(data)
	if err != nil {
		var validationErr *registry.ValidationError
		if errors.As(err, &validationErr) {
			fmt.Fprintf(stderr, "module registry blocked: code=%s\n", validationErr.Code)
		} else {
			fmt.Fprintln(stderr, "module registry blocked")
		}
		return exitBlocked
	}
	report := struct {
		SchemaVersion    string `json:"schema_version"`
		RegistryID       string `json:"registry_id"`
		ModuleCount      int    `json:"module_count"`
		PlanRequestCount int    `json:"plan_request_count"`
		Passed           bool   `json:"passed"`
	}{
		SchemaVersion:    registry.SchemaVersion,
		RegistryID:       parsed.RegistryID,
		ModuleCount:      len(parsed.Modules),
		PlanRequestCount: len(parsed.PlanRequests),
		Passed:           true,
	}
	if err := json.NewEncoder(stdout).Encode(report); err != nil {
		fmt.Fprintln(stderr, "module registry report unavailable")
		return exitUsage
	}
	return exitPassed
}
