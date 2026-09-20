// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type mustNotRead struct{ t *testing.T }

func (reader mustNotRead) Read([]byte) (int, error) {
	reader.t.Error("offline validation read credential input")
	return 0, io.EOF
}

func TestPublicCLIValidatesOfflineWithoutCredentialsOrStateMutation(t *testing.T) {
	directory := t.TempDir()
	profilePath := filepath.Join(directory, "profile.json")
	statePath := filepath.Join(directory, "installation")
	payload, _ := json.Marshal(testProfile())
	if err := os.WriteFile(profilePath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	code := RunCLI(context.Background(), []string{"dev", "validate", "--offline", "--profile", profilePath, "--state", statePath}, mustNotRead{t}, &output, &diagnostics)
	if code != 0 || diagnostics.Len() != 0 {
		t.Fatalf("offline CLI failed: %d %s", code, diagnostics.String())
	}
	var plan Plan
	if json.Unmarshal(output.Bytes(), &plan) != nil || plan.Profile != Development || plan.ProductionReady || len(plan.Objects) != 7 {
		t.Fatal("invalid public deterministic plan")
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("offline validation created state")
	}
}

func TestPublicCLIRejectsProductionUnknownArgumentsAndCredentialEcho(t *testing.T) {
	directory := t.TempDir()
	profilePath := filepath.Join(directory, "profile.json")
	profile := testProfile()
	profile.Profile = "production"
	payload, _ := json.Marshal(profile)
	if os.WriteFile(profilePath, payload, 0o600) != nil {
		t.Fatal("write profile")
	}
	var output, diagnostics bytes.Buffer
	if code := RunCLI(context.Background(), []string{"dev", "validate", "--offline", "--profile", profilePath}, strings.NewReader("secret-must-not-appear"), &output, &diagnostics); code == 0 {
		t.Fatal("production profile accepted")
	}
	if strings.Contains(output.String()+diagnostics.String(), "secret-must-not-appear") {
		t.Fatal("credential input echoed")
	}
	for _, arguments := range [][]string{{"dev", "adopt"}, {"dev", "create", "--force"}, {"dev", "destroy", "--connect", "--profile", profilePath, "--state", directory}, {"dev", "validate", "--profile", profilePath, "--timeout", "3h"}} {
		output.Reset()
		diagnostics.Reset()
		if RunCLI(context.Background(), arguments, strings.NewReader("secret-must-not-appear"), &output, &diagnostics) != 2 {
			t.Fatal("unsupported CLI arguments accepted")
		}
	}
}
