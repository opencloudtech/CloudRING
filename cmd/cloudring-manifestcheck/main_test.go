// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/opencloudtech/CloudRING/internal/platformmanifest"
)

func TestManifestReportSeparatesSourceContractFromLiveReadiness(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run(root, &stdout, &stderr); code != 0 {
		t.Fatalf("manifest verification failed: code=%d stderr=%q", code, stderr.String())
	}
	var output struct {
		Status     string                    `json:"status"`
		LiveStatus string                    `json:"liveStatus"`
		Profiles   []platformmanifest.Report `json:"profiles"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if output.Status != "source-contracts-verified" || output.LiveStatus != "blocked" {
		t.Fatalf("machine report overclaims readiness: %#v", output)
	}
	found := false
	for _, profile := range output.Profiles {
		if profile.Profile != "cloudring-postgresql-ha/v1" {
			continue
		}
		found = true
		if profile.Status != "source-contract-ready" || profile.LiveStatus != "blocked" || len(profile.Blockers) == 0 {
			t.Fatalf("PostgreSQL profile overclaims live readiness: %#v", profile)
		}
	}
	if !found {
		t.Fatal("PostgreSQL profile is missing from machine report")
	}
}
